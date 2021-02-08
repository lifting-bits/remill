/*
 * Copyright (c) 2018 Trail of Bits, Inc.
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

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <map>
#include <memory>
#include <sstream>
#include <string>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Instruction.h"
#include "remill/Arch/Name.h"
#include "remill/BC/IntrinsicTable.h"
#include "remill/BC/Lifter.h"
#include "remill/BC/Util.h"
#include "remill/OS/OS.h"
#include "tests/X86/Test.h"

#ifdef __APPLE__
#  define SYMBOL_PREFIX "_"
#else
#  define SYMBOL_PREFIX ""
#endif

DEFINE_string(bc_out, "",
              "Name of the file in which to place the generated bitcode.");

DECLARE_string(arch);
DECLARE_string(os);

namespace {

class TestTraceManager : public remill::TraceManager {
 public:
  virtual ~TestTraceManager(void) = default;

  void SetLiftedTraceDefinition(uint64_t addr,
                                llvm::Function *lifted_func) override {
    traces[addr] = lifted_func;
  }

  llvm::Function *GetLiftedTraceDeclaration(uint64_t addr) override {
    auto trace_it = traces.find(addr);
    if (trace_it != traces.end()) {
      return trace_it->second;
    } else {
      return nullptr;
    }
  }

  llvm::Function *GetLiftedTraceDefinition(uint64_t addr) override {
    return GetLiftedTraceDeclaration(addr);
  }

  bool TryReadExecutableByte(uint64_t addr, uint8_t *byte) override {
    auto byte_it = memory.find(addr);
    if (byte_it != memory.end()) {
      *byte = byte_it->second;
      return true;
    } else {
      return false;
    }
  }

 public:
  std::unordered_map<uint64_t, uint8_t> memory;
  std::unordered_map<uint64_t, llvm::Function *> traces;
};

}  // namespace

extern "C" int main(int argc, char *argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  DLOG(INFO) << "Generating tests.";

  std::vector<const test::TestInfo *> tests;
  for (auto i = 0U;; ++i) {
    const auto &test = test::__x86_test_table_begin[i];
    if (&test >= &(test::__x86_test_table_end[0])) {
      break;
    }
    tests.push_back(&test);
  }

  TestTraceManager manager;

  // Add all code byts from the test cases to the memory.
  for (auto test : tests) {
    for (auto addr = test->test_begin; addr < test->test_end; ++addr) {
      manager.memory[addr] = *reinterpret_cast<uint8_t *>(addr);
    }
  }

  llvm::LLVMContext context;
  auto os_name = remill::GetOSName(REMILL_OS);
  auto arch_name = remill::GetArchName(FLAGS_arch);
  auto arch = remill::Arch::Build(&context, os_name, arch_name);
  auto module = remill::LoadArchSemantics(arch);

  remill::IntrinsicTable intrinsics(module.get());
  remill::InstructionLifter inst_lifter(arch, intrinsics);
  remill::TraceLifter trace_lifter(inst_lifter, manager);

  for (auto test : tests) {
    if (!trace_lifter.Lift(test->test_begin)) {
      LOG(ERROR) << "Unable to lift test " << test->test_name;
      continue;
    }

    // Make sure the trace for the test has the right name.
    std::stringstream ss;
    ss << SYMBOL_PREFIX << test->test_name << "_lifted";

    auto lifted_trace = manager.GetLiftedTraceDefinition(test->test_begin);
    lifted_trace->setName(ss.str());
  }

  DLOG(INFO) << "Serializing bitcode to " << FLAGS_bc_out;
  auto host_arch =
      remill::Arch::Build(&context, os_name, remill::GetArchName(REMILL_ARCH));
  host_arch->PrepareModule(module.get());
  remill::StoreModuleToFile(module.get(), FLAGS_bc_out);

  DLOG(INFO) << "Done.";
  return 0;
}
