#include <glog/logging.h>
#include <gtest/gtest.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/GenericValue.h>
#include <llvm/ExecutionEngine/Interpreter.h>
#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/IR/Instructions.h>
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

enum TypeId { MEMORY = 0, STATE = 1 };

class LiftingTester {
 private:
  llvm::Module *semantics_module;
  remill::InstructionLifter::LifterPtr lifter;
  std::unique_ptr<remill::IntrinsicTable> table;
  remill::Arch::ArchPtr arch;

 public:
  LiftingTester(llvm::Module *semantics_module_, remill::OSName os_name,
                remill::ArchName arch_name)
      : semantics_module(semantics_module_) {
    this->arch = remill::Arch::Build(&semantics_module_->getContext(), os_name,
                                     arch_name);
    this->arch->InitFromSemanticsModule(semantics_module_);
    this->table =
        std::make_unique<remill::IntrinsicTable>(this->semantics_module);
    this->lifter = this->arch->DefaultLifter(*this->table.get());
  }

  std::unordered_map<TypeId, llvm::Type *> GetTypeMapping() {
    std::unordered_map<TypeId, llvm::Type *> res;

    auto ftype = this->arch->LiftedFunctionType();
    auto mem_type = llvm::cast<llvm::PointerType>(
        ftype->getParamType(remill::kMemoryPointerArgNum));
    auto state_type = llvm::cast<llvm::PointerType>(
        ftype->getParamType(remill::kStatePointerArgNum));


    res.emplace(TypeId::MEMORY, mem_type->getElementType());
    res.emplace(TypeId::STATE, state_type->getElementType());

    return res;
  }


  std::optional<std::pair<llvm::Function *, std::string>>
  LiftInstructionFunction(std::string_view fname, std::string_view bytes,
                          uint64_t address) {
    remill::Instruction insn;
    if (!this->arch->DecodeInstruction(address, bytes, insn)) {
      return std::nullopt;
    }

    LOG(INFO) << "Decoded insn " << insn.Serialize();

    auto target_func =
        this->arch->DefineLiftedFunction(fname, this->semantics_module);
    LOG(INFO) << "Func sig: "
              << remill::LLVMThingToString(target_func->getType());

    if (remill::LiftStatus::kLiftedInstruction ==
        this->lifter->LiftIntoBlock(insn, &target_func->getEntryBlock())) {


      auto mem_ptr_ref =
          remill::LoadMemoryPointerRef(&target_func->getEntryBlock());

      llvm::IRBuilder bldr(&target_func->getEntryBlock());
      auto pc_ref =
          remill::LoadProgramCounterRef(&target_func->getEntryBlock());
      auto next_pc_ref =
          remill::LoadNextProgramCounterRef(&target_func->getEntryBlock());
      bldr.CreateStore(bldr.CreateLoad(next_pc_ref), pc_ref);

      bldr.CreateRet(
          bldr.CreateLoad(this->lifter->GetMemoryType(), mem_ptr_ref));

      return std::make_pair(target_func, insn.function);
    } else {
      target_func->eraseFromParent();
      return std::nullopt;
    }
  }

  const remill::Arch::ArchPtr &GetArch() {
    return this->arch;
  }
};

static constexpr auto kFlagIntrinsicPrefix = "__remill_flag_computation";
static constexpr auto kCompareFlagIntrinsicPrefix = "__remill_compare";

bool flag_computation_stub(bool res, ...) {
  return res;
}

bool compare_instrinsic_stub(bool res) {
  return res;
}

class DiffModule {
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

  std::string_view GetNameF1() {
    return this->f1_insn_name;
  }

  std::string_view GetNameF2() {
    return this->f2_insn_name;
  }

 private:
  std::unique_ptr<llvm::Module> mod;
  llvm::Function *f1;
  llvm::Function *f2;
  std::string f1_insn_name;
  std::string f2_insn_name;
};


class MappTypeRemapper : public llvm::ValueMapTypeRemapper {
 private:
  const remill::TypeMap &tmap;

 public:
  MappTypeRemapper(const remill::TypeMap &tmap_) : tmap(tmap_) {}

  virtual llvm::Type *remapType(llvm::Type *SrcTy) override {
    LOG(INFO) << "Attempting to remap: " << remill::LLVMThingToString(SrcTy);
    if (this->tmap.find(SrcTy) != this->tmap.end()) {
      return this->tmap.find(SrcTy)->second;
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
    auto tmp_arch = remill::Arch::Build(context.get(), os_name_1, arch_name_1);
    auto semantics_module = remill::LoadArchSemantics(tmp_arch.get());
    tmp_arch->PrepareModule(semantics_module);
    auto l1 = LiftingTester(semantics_module.get(), os_name_1, arch_name_1);
    auto l2 = LiftingTester(semantics_module.get(), os_name_2, arch_name_2);

    return DifferentialModuleBuilder(std::move(context),
                                     std::move(semantics_module), std::move(l1),
                                     std::move(l2));
  }

 private:
  std::unique_ptr<llvm::LLVMContext> context;
  std::unique_ptr<llvm::Module> semantics_module;

  LiftingTester l1;
  LiftingTester l2;

  DifferentialModuleBuilder(std::unique_ptr<llvm::LLVMContext> context_,
                            std::unique_ptr<llvm::Module> semantics_module_,

                            LiftingTester l1_, LiftingTester l2_)
      : context(std::move(context_)),
        semantics_module(std::move(semantics_module_)),
        l1(std::move(l1_)),
        l2(std::move(l2_)) {}

 public:
  std::optional<DiffModule> build(std::string_view fname_f1,
                                  std::string_view fname_f2,
                                  std::string_view bytes, uint64_t address) {
    auto module = std::make_unique<llvm::Module>("", *this->context);
    auto maybe_f1 = this->l1.LiftInstructionFunction(fname_f1, bytes, address);
    auto maybe_f2 = this->l2.LiftInstructionFunction(fname_f2, bytes, address);

    if (maybe_f1.has_value() && maybe_f2.has_value()) {
      auto f1_and_name = *maybe_f1;
      auto f2_and_name = *maybe_f2;

      auto f1 = f1_and_name.first;
      auto f2 = f2_and_name.first;


      auto tst = f1->getParent();

      auto cloned = llvm::CloneModule(*tst);
      remill::OptimizeBareModule(cloned);

      auto new_f1 = llvm::Function::Create(
          f1->getFunctionType(), f1->getLinkage(), f1->getName(), module.get());
      auto new_f2 = llvm::Function::Create(
          f2->getFunctionType(), f2->getLinkage(), f2->getName(), module.get());

      remill::CloneFunctionInto(cloned->getFunction(f1->getName()), new_f1);
      remill::CloneFunctionInto(cloned->getFunction(f2->getName()), new_f2);


      return DiffModule(std::move(module), new_f1, new_f2, f1_and_name.second,
                        f2_and_name.second);
    } else {
      return std::nullopt;
    }
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
  llvm::ModulePassManager MPM = PB.buildPerModuleDefaultPipeline(
      llvm::PassBuilder::OptimizationLevel::O2);
}


using random_bytes_engine =
    std::independent_bits_engine<std::default_random_engine, CHAR_BIT, uint8_t>;


void *MissingFunctionStub(const std::string &name) {
  auto res = llvm::sys::DynamicLibrary::SearchForAddressOfSymbol(name);
  if (res) {
    return res;
  }
  LOG(FATAL) << "Missing function: " << name;
  return nullptr;
}


std::string PrintState(X86State *state) {
  return "";
}

struct DiffTestResult {
  std::string struct_dump1;
  std::string struct_dump2;
  bool are_equal;
};


class MemoryHandler {
 private:
  std::unordered_map<uint64_t, uint8_t> uninitialized_reads;
  std::unordered_map<uint64_t, uint8_t> state;

  random_bytes_engine rbe;
  llvm::support::endianness endian;

 public:
  MemoryHandler(llvm::support::endianness endian_) : endian(endian_) {}

  MemoryHandler(llvm::support::endianness endian_,
                std::unordered_map<uint64_t, uint8_t> initial_state)
      : state(std::move(initial_state)),
        endian(endian_) {}

  uint8_t read_byte(uint64_t addr) {
    if (state.find(addr) != state.end()) {
      return state.find(addr)->second;
    }

    auto genned = rbe();
    uninitialized_reads.insert({addr, genned});
    state.insert({addr, genned});
    return genned;
  }

  std::vector<uint8_t> readSize(uint64_t addr, size_t num) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < num; i++) {
      bytes.push_back(this->read_byte(addr + i));
    }
    return bytes;
  }

  const std::unordered_map<uint64_t, uint8_t> &GetMemory() const {
    return this->state;
  }

  std::string DumpState() const {

    llvm::json::Object mapping;
    for (const auto &kv : this->state) {
      std::stringstream ss;
      ss << kv.first;
      mapping[ss.str()] = kv.second;
    }

    std::string res;
    llvm::json::Value v(std::move(mapping));
    llvm::raw_string_ostream ss(res);
    ss << v;

    return ss.str();
  }

  template <class T>
  T ReadMemory(uint64_t addr) {
    auto buff = this->readSize(addr, sizeof(T));
    return llvm::support::endian::read<T>(buff.data(), this->endian);
  }


  template <class T>
  void WriteMemory(uint64_t addr, T value) {
    std::vector<uint8_t> buff(sizeof(T));
    llvm::support::endian::write<T>(buff.data(), value, this->endian);

    for (size_t i = 0; i < sizeof(T); i++) {
      this->state.insert({addr + i, buff[i]});
    }
  }

  std::unordered_map<uint64_t, uint8_t> GetUninitializedReads() {
    return this->uninitialized_reads;
  }
};

extern "C" {
uint8_t ___remill_undefined_8(void) {
  return 0;
}

uint32_t ___remill_read_memory_32(MemoryHandler *memory, uint64_t addr) {
  LOG(INFO) << "Reading " << std::hex << addr;
  auto res = memory->ReadMemory<uint32_t>(addr);
  LOG(INFO) << "Read memory " << res;
  return res;
}

MemoryHandler *___remill_write_memory_32(MemoryHandler *memory, uint64_t addr,
                                         uint32_t value) {
  LOG(INFO) << "Writing " << std::hex << addr;
  memory->WriteMemory<uint32_t>(addr, value);
  return memory;
}

uint64_t ___remill_read_memory_64(MemoryHandler *memory, uint64_t addr) {
  LOG(INFO) << "Reading " << std::hex << addr;
  return memory->ReadMemory<uint64_t>(addr);
}

MemoryHandler *___remill_write_memory_64(MemoryHandler *memory, uint64_t addr,
                                         uint64_t value) {
  LOG(INFO) << "Writing " << std::hex << addr;
  memory->WriteMemory<uint64_t>(addr, value);
  return memory;
}
}


class ComparisonRunner {
 private:
  random_bytes_engine rbe;
  llvm::support::endianness endian;

  void RandomizeState(X86State *state) {
    std::vector<uint8_t> data(sizeof(X86State));
    std::generate(begin(data), end(data), std::ref(rbe));

    std::memcpy(state, data.data(), sizeof(X86State));
  }

 public:
  ComparisonRunner(llvm::support::endianness endian_) : endian(endian_) {}

 private:
  void ExecuteLiftedFunction(llvm::Function *func, size_t insn_length,
                             X86State *state, MemoryHandler *handler) {
    std::string load_error = "";
    llvm::sys::DynamicLibrary::LoadLibraryPermanently(nullptr, &load_error);
    if (!load_error.empty()) {
      LOG(FATAL) << "Failed to load: " << load_error;
    }

    auto tgt_mod = llvm::CloneModule(*func->getParent());
    tgt_mod->setTargetTriple("");
    tgt_mod->setDataLayout(llvm::DataLayout(""));
    llvm::InitializeNativeTarget();
    llvm::InitializeNativeTargetAsmParser();
    llvm::InitializeNativeTargetAsmPrinter();
    llvm::InitializeAllTargetMCs();

    auto res = remill::VerifyModuleMsg(tgt_mod.get());
    if (res.has_value()) {
      LOG(FATAL) << *res;
    }

    llvm::EngineBuilder builder(std::move(tgt_mod));


    std::string estr;
    auto eptr = builder.setEngineKind(llvm::EngineKind::JIT)
                    .setErrorStr(&estr)
                    .create();

    if (eptr == nullptr) {
      LOG(FATAL) << estr;
    }

    std::unique_ptr<llvm::ExecutionEngine> engine(eptr);


    auto target = engine->FindFunctionNamed(func->getName());
    this->StubOutFlagComputationInstrinsics(target->getParent(), *engine);

    engine->InstallLazyFunctionCreator(&MissingFunctionStub);
    engine->DisableSymbolSearching(false);
    // expect traditional remill lifted insn
    assert(func->arg_size() == 3);

    auto returned =
        (void *(*) (X86State *, uint32_t, void *) ) engine->getFunctionAddress(
            target->getName().str());

    assert(returned != nullptr);
    returned(state, state->gpr.rip.dword, handler);
  }

  void StubOutFlagComputationInstrinsics(llvm::Module *mod,
                                         llvm::ExecutionEngine &exec_engine) {
    for (auto &func : mod->getFunctionList()) {
      if (func.isDeclaration() &&
          func.getName().startswith(kFlagIntrinsicPrefix)) {
        exec_engine.addGlobalMapping(&func, (void *) &flag_computation_stub);
      }

      if (func.isDeclaration() &&
          func.getName().startswith(kCompareFlagIntrinsicPrefix)) {
        exec_engine.addGlobalMapping(&func, (void *) &compare_instrinsic_stub);
      }
    }
  }


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
    RandomizeState(func1_state);
    func1_state->addr.ds_base.dword = 0;
    func1_state->addr.ss_base.dword = 0;
    func1_state->addr.es_base.dword = 0;
    func1_state->addr.cs_base.dword = 0;
    auto func2_state = (X86State *) alloca(sizeof(X86State));

    std::memcpy(func2_state, func1_state, sizeof(X86State));

    assert(std::memcmp(func1_state, func2_state, sizeof(X86State)) == 0);

    auto mem_handler = std::make_unique<MemoryHandler>(this->endian);
    ExecuteLiftedFunction(f1, insn_length, func1_state, mem_handler.get());
    auto second_handler = std::make_unique<MemoryHandler>(
        this->endian, mem_handler->GetUninitializedReads());
    ExecuteLiftedFunction(f2, insn_length, func2_state, second_handler.get());


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


    return {this->DumpState(func1_state), this->DumpState(func2_state),
            are_equal};
  }
};

struct TestCase {
  uint64_t addr;
  std::string bytes;
};

namespace llvm::json {
bool fromJSON(const Value &E, TestCase &Out, Path P) {
  auto maybe_array = E.getAsArray();
  if (!maybe_array) {
    P.report("Should be array");
    return false;
  }

  if (maybe_array->size() != 2) {
    P.report("Expected two elements");
    return false;
  }

  auto array = *maybe_array;

  auto addr = array[0];
  auto maybe_addr = addr.getAsInteger();
  if (!maybe_addr.hasValue()) {
    P.report("Expected integer address");
    return false;
  }

  auto byte_string = array[1].getAsString();

  if (!byte_string.hasValue()) {
    P.report("Expected hex string of instruction bytes");
    return false;
  }

  auto bytes = llvm::fromHex(byte_string.getValue());

  Out.addr = maybe_addr.getValue();
  Out.bytes = bytes;
  return true;
}
};  // namespace llvm::json


std::string test_case_name(std::string_view prefix, uint64_t test_cast_ctr) {
  std::stringstream ss;
  ss << prefix << "comp_func" << test_cast_ctr;
  return ss.str();
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
  auto succeeded = true;
  for (auto tc : testcases) {
    LOG(INFO) << "Starting testcase: " << llvm::toHex(tc.bytes);
    auto diff_mod =
        diffbuilder.build(test_case_name("f1", ctr), test_case_name("f2", ctr),
                          tc.bytes, tc.addr);

    if (!diff_mod.has_value()) {
      LOG(ERROR) << "Failed to lift " << std::hex << tc.addr << ": "
                 << llvm::toHex(tc.bytes);
      continue;
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
        succeeded = false;
        LOG(ERROR) << "Difference in instruction" << std::hex << tc.addr << ": "
                   << llvm::toHex(tc.bytes);

        std::cout << tc_result.struct_dump1 << std::endl;
        std::cout << tc_result.struct_dump2 << std::endl;

        failed_testcases.push_back(tc);
        if (!FLAGS_repro_file.empty()) {
          std::error_code ec;
          llvm::raw_fd_ostream o(FLAGS_repro_file, ec);
          if (ec) {
            LOG(FATAL) << ec.message();
          }

          llvm::json::Array arr;
          for (auto tc : failed_testcases) {
            arr.push_back(
                llvm::json::Array({llvm::json::Value(tc.addr),
                                   llvm::json::Value(llvm::toHex(tc.bytes))}));
          }

          llvm::json::operator<<(o, llvm::json::Value(std::move(arr)));
        }
      }

      if (!succeeded && FLAGS_stop_on_fail) {
        return 1;
      }
    }
    ctr++;
  }

  if (succeeded) {
    return 0;
  } else {
    return 1;
  }
}
