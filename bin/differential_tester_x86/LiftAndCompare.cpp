/*
 * Copyright (c) 2022 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <llvm/ADT/StringExtras.h>
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
#include <remill/BC/Version.h>
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


struct InstructionFunction {
  llvm::Function *llvm_function;
  std::string isel_name;
};

class DiffModule {
 private:
  std::unique_ptr<llvm::Module> mod;

  std::tuple<InstructionFunction, InstructionFunction> functions_to_compare;

 public:
  DiffModule(std::unique_ptr<llvm::Module> mod_, llvm::Function *f1_,
             llvm::Function *f2_, std::string f1_insn_name_,
             std::string f2_insn_name_)
      : mod(std::move(mod_)),
        functions_to_compare({{f1_, f1_insn_name_}, {f2_, f2_insn_name_}}) {}

  llvm::Module *GetModule() {
    return this->mod.get();
  }

  template <std::size_t N>
  InstructionFunction GetF() const {
    return std::get<N>(this->functions_to_compare);
  }
};

class DifferentialModuleBuilder {
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

 public:
  static DifferentialModuleBuilder
  Create(remill::OSName os_name_1, remill::ArchName arch_name_1,
         remill::OSName os_name_2, remill::ArchName arch_name_2) {
    // it is expected that compatible arches share a semantics module.
    std::unique_ptr<llvm::LLVMContext> context =
        std::make_unique<llvm::LLVMContext>();
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

    for (auto x : {f1, f2}) {
      CHECK(remill::VerifyFunction(x));
    }


    auto tst = f1->getParent();

    CHECK(remill::VerifyModule(tst));

    auto cloned = llvm::CloneModule(*tst);

    if (auto maybe_message = remill::VerifyModuleMsg(cloned.get())) {
      LOG(FATAL) << *maybe_message;
    }

    remill::OptimizeBareModule(cloned);

    auto new_f1 =
        test_runner::CopyFunctionIntoNewModule(module.get(), f1, cloned);
    auto new_f2 =
        test_runner::CopyFunctionIntoNewModule(module.get(), f2, cloned);


    return DiffModule(std::move(module), new_f1, new_f2,
                      f1_and_name.second.function, f2_and_name.second.function);
  }
};

using random_bytes_engine =
    std::independent_bits_engine<std::default_random_engine, CHAR_BIT, uint16_t>;


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
  llvm::endianness endian;


 public:
  ComparisonRunner(llvm::endianness endian_) : endian(endian_) {}

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

    X86State func1_state{};
    test_runner::RandomizeState(func1_state, this->rbe);
    func1_state.addr.ds_base.dword = 0;
    func1_state.addr.ss_base.dword = 0;
    func1_state.addr.es_base.dword = 0;
    func1_state.addr.cs_base.dword = 0;
    func1_state.aflag.af = test_runner::random_boolean_flag(this->rbe);
    func1_state.aflag.cf = test_runner::random_boolean_flag(this->rbe);
    func1_state.aflag.df = test_runner::random_boolean_flag(this->rbe);
    func1_state.aflag.of = test_runner::random_boolean_flag(this->rbe);
    func1_state.aflag.pf = test_runner::random_boolean_flag(this->rbe);
    func1_state.aflag.sf = test_runner::random_boolean_flag(this->rbe);
    func1_state.aflag.zf = test_runner::random_boolean_flag(this->rbe);

    if (isel_name.rfind("REP_") != std::string::npos) {
      LOG(INFO) << "setting ecx to 1";
      func1_state.gpr.rcx.dword = 1;
    }

    X86State func2_state{};

    auto init_state = this->DumpState(&func1_state);

    std::memcpy(&func2_state, &func1_state, sizeof(X86State));

    auto mem_handler =
        std::make_unique<test_runner::MemoryHandler>(this->endian);
    auto pc_fetch = [](X86State *st) { return st->gpr.rip.qword; };
    test_runner::ExecuteLiftedFunction<X86State>(f1, insn_length, &func1_state,
                                                 mem_handler.get(), pc_fetch);
    auto second_handler = std::make_unique<test_runner::MemoryHandler>(
        this->endian, mem_handler->GetUninitializedReads());
    test_runner::ExecuteLiftedFunction<X86State>(
        f2, insn_length, &func2_state, second_handler.get(), pc_fetch);


    auto memory_state_eq =
        mem_handler->GetMemory() == second_handler->GetMemory();

    // NOTE(Ian): Here we log differences in instructions that arise from a different memory interaction.
    if (!memory_state_eq) {
      LOG(ERROR) << "Memory state differs";
      LOG(ERROR) << mem_handler->DumpState();
      LOG(ERROR) << second_handler->DumpState();
    }

    for (const auto &it : whitelist) {
      it.ApplyToInsn(isel_name, &func1_state);
      it.ApplyToInsn(isel_name, &func2_state);
    }

    auto are_equal =
        std::memcmp(&func1_state, &func2_state, sizeof(X86State)) == 0 &&
        memory_state_eq;


    return {init_state, this->DumpState(&func1_state),
            this->DumpState(&func2_state), are_equal};
  }
};

struct TestCase {
  uint64_t addr;
  std::string bytes;
};

namespace llvm::json {
bool fromJSON(const Value &E, TestCase &Out, Path P) {
  auto byte_string = E.getAsString();
  if (!byte_string) {
    P.report("Expected hex string of instruction bytes");
    return false;
  }

  auto bytes = llvm::fromHex(*byte_string);

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
                 ? llvm::endianness::big
                 : llvm::endianness::little;
  ComparisonRunner comp_runner(end);

  if (FLAGS_should_dump_functions) {
    LOG(INFO) << remill::LLVMThingToString(diff_mod->GetF<0>().llvm_function);
    LOG(INFO) << remill::LLVMThingToString(diff_mod->GetF<1>().llvm_function);
  }

  for (uint64_t i = 0; i < FLAGS_num_iterations; i++) {
    auto tc_result = comp_runner.SingleCmpRun(
        tc.bytes.size(), diff_mod->GetF<0>().llvm_function,
        diff_mod->GetF<1>().llvm_function, whitelist,
        diff_mod->GetF<0>().isel_name);

    if (!tc_result.are_equal) {
      LOG(ERROR) << "Difference in instruction" << std::hex << tc.addr << ": "
                 << llvm::toHex(tc.bytes);
      LOG(INFO) << "Init state: " << tc_result.init_state_dump << std::endl;
      LOG(INFO) << tc_result.struct_dump1 << std::endl;
      LOG(INFO) << tc_result.struct_dump2 << std::endl;
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
    llvm::errs() << llvm::toHex(tc.bytes) << "\n";
    llvm::errs().flush();
    
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


  return succeeded_tot ? 0 : 2;
}
