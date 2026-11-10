/*
 * Copyright (c) 2026 Trail of Bits, Inc.
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

#pragma once

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Instruction.h>
#include <remill/Arch/Name.h>
#include <remill/BC/Optimizer.h>
#include <remill/OS/OS.h>
#include <test_runner/TestOutputSpec.h>
#include <test_runner/TestRunner.h>

#include <functional>
#include <sstream>
#include <string>

namespace sparc_test {

// Lifts one SPARC instruction (with Sleigh, a delayed control transfer
// includes its delay slot), runs it on a randomized state with the test's
// preconditions, and checks the decoded category and the resulting state.
template <typename S>
class TestSpecRunner {
 public:
  TestSpecRunner(llvm::LLVMContext &context, remill::ArchName arch_name,
                 std::function<uint64_t(S *)> program_counter)
      : lifter(context, remill::OSName::kOSLinux, arch_name),
        program_counter(std::move(program_counter)) {}

  void RunTestSpec(const test_runner::TestOutputSpec<S> &test) {
    std::stringstream ss;
    ss << "test_disas_func_" << this->test_counter++;

    auto maybe_func = lifter.LiftInstructionFunction(
        ss.str(), test.target_bytes, test.addr,
        lifter.GetArch()->CreateInitialContext());
    ASSERT_TRUE(maybe_func.has_value());
    auto lifted_func = maybe_func->first;

    // Optimize a copy of the module to drop the unused intrinsics, and run
    // the lifted function from a module of its own.
    auto new_mod = llvm::CloneModule(*lifted_func->getParent());
    remill::OptimizeBareModule(new_mod.get());
    auto just_func_mod =
        std::make_unique<llvm::Module>("", new_mod->getContext());
    auto new_func = test_runner::CopyFunctionIntoNewModule(
        just_func_mod.get(), lifted_func, new_mod);

    test.CheckLiftedInstruction(maybe_func->second);

    S state = {};
    test_runner::RandomizeState(state, this->rbe);
    test.SetupTestPreconditions(state);

    test_runner::MemoryHandler memory(llvm::endianness::big);
    for (const auto &prec : test.GetMemoryPrecs()) {
      prec(memory);
    }

    test_runner::ExecuteLiftedFunction<S>(new_func, test.target_bytes.size(),
                                          &state, &memory,
                                          this->program_counter);

    test.CheckResultingState(state);
    test.CheckResultingMemory(memory);
  }

 private:
  test_runner::LiftingTester lifter;
  std::function<uint64_t(S *)> program_counter;
  test_runner::random_bytes_engine rbe;
  uint64_t test_counter{0};
};

}  // namespace sparc_test
