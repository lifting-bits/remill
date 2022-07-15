#include <fenv.h>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/GenericValue.h>
#include <llvm/ExecutionEngine/Interpreter.h>
#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/DynamicLibrary.h>
#include <llvm/Support/Endian.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/Arch/X86/Runtime/State.h>
#include <remill/BC/ABI.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Optimizer.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>
#include <test_runner/TestRunner.h>

#include <functional>
#include <random>

#include "Whitelist.h"
#include "gtest/gtest.h"


DEFINE_string(target_insn_file, "", "Path to input test cases");
DEFINE_uint64(num_iterations, 2, "number of iterations per test case");
DEFINE_string(repro_file, "", "File to output failing test cases");
DEFINE_string(whitelist, "", "File listing instruction states not to check");
DEFINE_bool(should_dump_functions, false, "Dump each function version");
DEFINE_bool(stop_on_fail, false, "Stop on first failure");


class DiffModule {
 private:
  std::unique_ptr<llvm::Module> mod;
  llvm::Function *f1;
  llvm::Function *f2;
  std::string f1_insn_name;
  std::string f2_insn_name;

 public:
  DiffModule(std::unique_ptr<llvm::Module> mod_, llvm::Function *f1_,
             llvm::Function *f2_, std::string f1_insn_name_,
             std::string f2_insn_name_)
      : mod(std::move(mod_)),
        f1(f1_),
        f2(f2_),
        f1_insn_name(f1_insn_name_),
        f2_insn_name(f2_insn_name_) {}

  llvm::Module *GetModule() {
    return this->mod.get();
  }

  llvm::Function *GetF1() {
    return this->f1;
  }

  llvm::Function *GetF2() {
    return this->f2;
  }

  std::string_view GetNameF1() const {
    return this->f1_insn_name;
  }

  std::string_view GetNameF2() const {
    return this->f2_insn_name;
  }
};


class MappTypeRemapper : public llvm::ValueMapTypeRemapper {
 private:
  const remill::TypeMap &tmap;

 public:
  MappTypeRemapper(const remill::TypeMap &tmap_) : tmap(tmap_) {}

  virtual llvm::Type *remapType(llvm::Type *SrcTy) override {
    LOG(INFO) << "Attempting to remap: " << remill::LLVMThingToString(SrcTy);
    if (auto it = this->tmap.find(SrcTy); it != this->tmap.end()) {
      return it->second;
    }

    return SrcTy;
  }
};

void CloneFunctionWithTypeMap(llvm::Function *NewFunc, llvm::Function *OldFunc,
                              remill::TypeMap &tmap) {

  remill::ValueMap vmap;
  remill::MDMap md_map;
  remill::CloneFunctionInto(OldFunc, NewFunc, vmap, tmap, md_map);
}

class DifferentialModuleBuilder {
 public:
  static DifferentialModuleBuilder
  Create(remill::OSName os_name_1, remill::ArchName arch_name_1,
         remill::OSName os_name_2, remill::ArchName arch_name_2) {
    // it is expected that compatible arches share a semantics module.
    std::unique_ptr<llvm::LLVMContext> context =
        std::make_unique<llvm::LLVMContext>();
    context->enableOpaquePointers();
    auto tmp_arch = remill::Arch::Build(context.get(), os_name_1, arch_name_1);
    std::shared_ptr<llvm::Module> semantics_module =
        remill::LoadArchSemantics(tmp_arch.get());
    tmp_arch->PrepareModule(semantics_module.get());
    auto l1 =
        test_runner::LiftingTester(semantics_module, os_name_1, arch_name_1);
    auto l2 =
        test_runner::LiftingTester(semantics_module, os_name_2, arch_name_2);
    return DifferentialModuleBuilder(std::move(context),
                                     std::move(semantics_module), std::move(l1),
                                     std::move(l2));
  }

 private:
  std::unique_ptr<llvm::LLVMContext> context;
  std::shared_ptr<llvm::Module> semantics_module;

  test_runner::LiftingTester l1;
  test_runner::LiftingTester l2;

  DifferentialModuleBuilder(std::unique_ptr<llvm::LLVMContext> context_,
                            std::shared_ptr<llvm::Module> semantics_module_,

                            test_runner::LiftingTester l1_,
                            test_runner::LiftingTester l2_)
      : context(std::move(context_)),
        semantics_module(std::move(semantics_module_)),
        l1(std::move(l1_)),
        l2(std::move(l2_)) {}

  static llvm::Function *
  CopyFunctionIntoNewModule(llvm::Module *target,
                            const llvm::Function *old_func,
                            const std::unique_ptr<llvm::Module> &old_module) {
    auto new_f = llvm::Function::Create(old_func->getFunctionType(),
                                        old_func->getLinkage(),
                                        old_func->getName(), target);
    remill::CloneFunctionInto(old_module->getFunction(old_func->getName()),
                              new_f);
    return new_f;
  }

 public:
  std::optional<DiffModule> build(std::string_view fname_f1,
                                  std::string_view fname_f2,
                                  std::string_view bytes, uint64_t address) {
    auto module = std::make_unique<llvm::Module>("", *this->context);
    auto maybe_f1 = this->l1.LiftInstructionFunction(fname_f1, bytes, address);
    auto maybe_f2 = this->l2.LiftInstructionFunction(fname_f2, bytes, address);

    if (!maybe_f1.has_value() || !maybe_f2.has_value()) {
      return std::nullopt;
    }

    auto f1_and_name = *maybe_f1;
    auto f2_and_name = *maybe_f2;

    auto f1 = f1_and_name.first;
    auto f2 = f2_and_name.first;
    llvm::verifyFunction(*f1, &llvm::errs());

    llvm::verifyFunction(*f2, &llvm::errs());


    auto tst = f1->getParent();

    for (const auto &f : tst->getFunctionList()) {
      if (llvm::verifyFunction(f, &llvm::errs())) {

        f.dump();
        LOG(INFO) << "Num basic block: " << f.getBasicBlockList().size();
        LOG(FATAL) << "Error in " << f.getName().str();
      }
    }

    assert(remill::VerifyModule(tst));

    auto cloned = llvm::CloneModule(*tst);

    auto maybe_message = remill::VerifyModuleMsg(cloned.get());
    if (maybe_message.has_value()) {
      cloned->getFunction(f1->getName())->dump();
      cloned->getFunction(f2->getName())->dump();
      auto insn_func =
          cloned->getFunction("sleigh_remill_instruction_function");
      if (insn_func) {
        insn_func->dump();
      }

      LOG(FATAL) << *maybe_message;
    }

    remill::OptimizeBareModule(cloned);

    auto new_f1 = DifferentialModuleBuilder::CopyFunctionIntoNewModule(
        module.get(), f1, cloned);
    auto new_f2 = DifferentialModuleBuilder::CopyFunctionIntoNewModule(
        module.get(), f2, cloned);


    return DiffModule(std::move(module), new_f1, new_f2,
                      f1_and_name.second.function, f2_and_name.second.function);
  }
};

void RunDefaultOptPipeline(llvm::Module *mod) {
  // Create the analysis managers.
  llvm::LoopAnalysisManager LAM;
  llvm::FunctionAnalysisManager FAM;
  llvm::CGSCCAnalysisManager CGAM;
  llvm::ModuleAnalysisManager MAM;

  // Create the new pass manager builder.
  // Take a look at the PassBuilder constructor parameters for more
  // customization, e.g. specifying a TargetMachine or various debugging
  // options.
  llvm::PassBuilder PB;

  // Register all the basic analyses with the managers.
  PB.registerModuleAnalyses(MAM);
  PB.registerCGSCCAnalyses(CGAM);
  PB.registerFunctionAnalyses(FAM);
  PB.registerLoopAnalyses(LAM);
  PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

  // Create the pass manager.
  // This one corresponds to a typical -O2 optimization pipeline.
  llvm::ModulePassManager MPM =
      PB.buildPerModuleDefaultPipeline(llvm::OptimizationLevel::O2);
}


using random_bytes_engine =
    std::independent_bits_engine<std::default_random_engine, CHAR_BIT, uint8_t>;


std::string PrintState(X86State *state) {
  return "";
}

struct DiffTestResult {
  std::string init_state_dump;
  std::string struct_dump1;
  std::string struct_dump2;
  bool are_equal;
};


class ComparisonRunner {
 private:
  random_bytes_engine rbe;
  llvm::support::endianness endian;


 public:
  ComparisonRunner(llvm::support::endianness endian_) : endian(endian_) {}

 private:
  template <class T>
  void addRegTo(llvm::json::Object &obj, std::string name, T value) {
    obj[name] = value;
  }


  std::string DumpState(X86State *st) {

    llvm::json::Object mapper;
    llvm::json::Object gpr;
    addRegTo(gpr, "eax", st->gpr.rax.dword);
    addRegTo(gpr, "ebx", st->gpr.rbx.dword);
    addRegTo(gpr, "ecx", st->gpr.rcx.dword);
    addRegTo(gpr, "edx", st->gpr.rdx.dword);
    addRegTo(gpr, "eip", st->gpr.rip.dword);
    addRegTo(gpr, "esp", st->gpr.rsp.dword);
    addRegTo(gpr, "esi", st->gpr.rsi.dword);
    addRegTo(gpr, "edi", st->gpr.rdi.dword);


    llvm::json::Object flags;
    addRegTo(flags, "zf", st->aflag.zf);
    addRegTo(flags, "of", st->aflag.of);
    addRegTo(flags, "pf", st->aflag.pf);
    addRegTo(flags, "cf", st->aflag.cf);
    addRegTo(flags, "df", st->aflag.df);
    addRegTo(flags, "sf", st->aflag.sf);
    addRegTo(flags, "af", st->aflag.af);


    mapper["gpr"] = std::move(gpr);
    mapper["flags"] = std::move(flags);
    std::string res;
    llvm::json::Value v(std::move(mapper));
    llvm::raw_string_ostream ss(res);
    ss << v;

    return ss.str();
  }

 public:
  DiffTestResult
  SingleCmpRun(size_t insn_length, llvm::Function *f1, llvm::Function *f2,
               const std::vector<WhiteListInstruction> &whitelist,
               std::string_view isel_name) {

    auto func1_state = (X86State *) alloca(sizeof(X86State));
    test_runner::RandomizeState(func1_state, this->rbe);
    func1_state->addr.ds_base.dword = 0;
    func1_state->addr.ss_base.dword = 0;
    func1_state->addr.es_base.dword = 0;
    func1_state->addr.cs_base.dword = 0;
    func1_state->aflag.af = test_runner::random_boolean_flag(this->rbe);
    func1_state->aflag.cf = test_runner::random_boolean_flag(this->rbe);
    func1_state->aflag.df = test_runner::random_boolean_flag(this->rbe);
    func1_state->aflag.of = test_runner::random_boolean_flag(this->rbe);
    func1_state->aflag.pf = test_runner::random_boolean_flag(this->rbe);
    func1_state->aflag.sf = test_runner::random_boolean_flag(this->rbe);
    func1_state->aflag.zf = test_runner::random_boolean_flag(this->rbe);

    if (isel_name.rfind("REP_") != std::string::npos) {
      LOG(INFO) << "setting ecx to 1";
      func1_state->gpr.rcx.dword = 1;
    }

    auto func2_state = (X86State *) alloca(sizeof(X86State));

    auto init_state = this->DumpState(func1_state);

    std::memcpy(func2_state, func1_state, sizeof(X86State));

    assert(std::memcmp(func1_state, func2_state, sizeof(X86State)) == 0);

    auto mem_handler =
        std::make_unique<test_runner::MemoryHandler>(this->endian);
    std::function<uint64_t(X86State * st)> pc_fetch = [](X86State *st) {
      return st->gpr.rip.qword;
    };
    test_runner::ExecuteLiftedFunction<X86State, uint64_t>(
        f1, insn_length, func1_state, mem_handler.get(), pc_fetch);
    auto second_handler = std::make_unique<test_runner::MemoryHandler>(
        this->endian, mem_handler->GetUninitializedReads());
    test_runner::ExecuteLiftedFunction<X86State, uint64_t>(
        f2, insn_length, func2_state, second_handler.get(), pc_fetch);


    auto memory_state_eq =
        mem_handler->GetMemory() == second_handler->GetMemory();

    if (!memory_state_eq) {
      LOG(ERROR) << "Memory state differs";
      LOG(ERROR) << mem_handler->DumpState();
      LOG(ERROR) << second_handler->DumpState();
    }

    for (const auto &it : whitelist) {
      it.ApplyToInsn(isel_name, func1_state);
      it.ApplyToInsn(isel_name, func2_state);
    }

    auto are_equal =
        std::memcmp(func1_state, func2_state, sizeof(X86State)) == 0 &&
        memory_state_eq;


    return {init_state, this->DumpState(func1_state),
            this->DumpState(func2_state), are_equal};
  }
};

struct TestCase {
  uint64_t addr;
  std::string bytes;
};

namespace llvm::json {
bool fromJSON(const Value &E, TestCase &Out, Path P) {
  auto byte_string = E.getAsString();
  if (!byte_string.hasValue()) {
    P.report("Expected hex string of instruction bytes");
    return false;
  }

  auto bytes = llvm::fromHex(byte_string.getValue());

  Out.bytes = bytes;
  // Should maybe do something else here?
  Out.addr = 0xdeadbe00;
  return true;
}
};  // namespace llvm::json


std::string test_case_name(std::string_view prefix, uint64_t test_cast_ctr) {
  std::stringstream ss;
  ss << prefix << "comp_func" << test_cast_ctr;
  return ss.str();
}

// Returns true when test case succeeds
bool runTestCase(const TestCase &tc, DifferentialModuleBuilder &diffbuilder,
                 const std::vector<WhiteListInstruction> &whitelist,
                 uint64_t ctr) {
  LOG(INFO) << "Starting testcase: " << llvm::toHex(tc.bytes);
  auto diff_mod = diffbuilder.build(
      test_case_name("f1", ctr), test_case_name("f2", ctr), tc.bytes, tc.addr);

  if (!diff_mod.has_value()) {
    LOG(ERROR) << "Failed to lift " << std::hex << tc.addr << ": "
               << llvm::toHex(tc.bytes);

    if (FLAGS_stop_on_fail) {
      LOG(FATAL) << "Failed to lift an insn";
    }
    return false;
  }

  auto end = diff_mod->GetModule()->getDataLayout().isBigEndian()
                 ? llvm::support::endianness::big
                 : llvm::support::endianness::little;
  ComparisonRunner comp_runner(end);

  if (FLAGS_should_dump_functions) {
    LOG(INFO) << remill::LLVMThingToString(diff_mod->GetF1());
    LOG(INFO) << remill::LLVMThingToString(diff_mod->GetF2());
  }

  for (uint64_t i = 0; i < FLAGS_num_iterations; i++) {
    auto tc_result = comp_runner.SingleCmpRun(
        tc.bytes.size(), diff_mod->GetF1(), diff_mod->GetF2(), whitelist,
        diff_mod->GetNameF1());

    if (!tc_result.are_equal) {
      LOG(ERROR) << "Difference in instruction" << std::hex << tc.addr << ": "
                 << llvm::toHex(tc.bytes);
      std::cout << "Init state: " << tc_result.init_state_dump << std::endl;
      std::cout << tc_result.struct_dump1 << std::endl;
      std::cout << tc_result.struct_dump2 << std::endl;
      return false;
    }
  }

  return true;
}


int main(int argc, char **argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);


  if (FLAGS_target_insn_file.empty()) {
    LOG(FATAL) << "Must provide a test case file";
  }

  auto maybe_buff = llvm::MemoryBuffer::getFileOrSTDIN(FLAGS_target_insn_file);

  if (maybe_buff.getError()) {
    LOG(FATAL) << "Failed to read file with: "
               << maybe_buff.getError().message();
  }

  auto maybe_json = llvm::json::parse(maybe_buff.get()->getBuffer());
  if (auto E = maybe_json.takeError()) {
    LOG(FATAL) << "Failed to parse json: " << llvm::toString(std::move(E));
  }


  std::vector<TestCase> testcases;
  llvm::json::Path::Root root;
  llvm::json::Path pth(root);

  if (!llvm::json::fromJSON(maybe_json.get(), testcases, pth)) {
    LOG(FATAL) << "Failed to parse testcases";
  }

  std::vector<WhiteListInstruction> whitelist;

  if (!FLAGS_whitelist.empty()) {
    LOG(INFO) << "Reading whitelist";
    auto maybe_whitelist_buff =
        llvm::MemoryBuffer::getFileOrSTDIN(FLAGS_whitelist);
    if (maybe_whitelist_buff.getError()) {
      LOG(FATAL) << "Failed to read whitelist file with: "
                 << maybe_whitelist_buff.getError().message();
    }

    auto maybe_whitelist_json =
        llvm::json::parse<std::vector<WhiteListInstruction>>(
            maybe_whitelist_buff.get()->getBuffer());
    if (auto E = maybe_whitelist_json.takeError()) {
      LOG(FATAL) << "Failed to parse whitelist json: "
                 << llvm::toString(std::move(E));
    }

    whitelist = maybe_whitelist_json.get();
  } else {
    LOG(ERROR) << "Not using a whitelist";
  }

  DifferentialModuleBuilder diffbuilder = DifferentialModuleBuilder::Create(
      remill::OSName::kOSLinux, remill::ArchName::kArchX86,
      remill::OSName::kOSLinux, remill::ArchName::kArchX86_SLEIGH);
  uint64_t ctr = 0;

  std::vector<TestCase> failed_testcases;
  auto succeeded_tot = true;
  for (auto tc : testcases) {
    auto tc_succeeded = runTestCase(tc, diffbuilder, whitelist, ++ctr);
    if (!tc_succeeded) {
      succeeded_tot = false;
      failed_testcases.push_back(tc);
    }

    if (!FLAGS_repro_file.empty() && !tc_succeeded) {
      std::error_code ec;
      llvm::raw_fd_ostream o(FLAGS_repro_file, ec);
      if (ec) {
        LOG(FATAL) << ec.message();
      }

      llvm::json::Array arr;
      for (auto tc : failed_testcases) {
        arr.push_back(llvm::toHex(tc.bytes));
      }

      llvm::json::operator<<(o, llvm::json::Value(std::move(arr)));
    }

    if (!succeeded_tot && FLAGS_stop_on_fail) {
      return 2;
    }
  }

  if (succeeded_tot) {
    return 0;
  } else {
    return 2;
  }
}
