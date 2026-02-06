/*
 * Copyright (c) 2026-present Trail of Bits, Inc.
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

#include <gtest/gtest.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <remill/Arch/Name.h>
#include <remill/BC/Optimizer.h>
#include <test_runner/TestRunner.h>

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#include <remill/Arch/RISCV/Runtime/State.h>

namespace riscv::test {

template <remill::ArchName kArch>
struct ArchTraits;

template <>
struct ArchTraits<remill::ArchName::kArchRISCV32> {
  static uint64_t FetchPC(RISCVState *st) {
    return static_cast<uint64_t>(st->pc.dword);
  }

  static void SetPC(RISCVState *st, uint64_t pc) {
    st->pc.dword = static_cast<uint32_t>(pc);
  }
};

template <>
struct ArchTraits<remill::ArchName::kArchRISCV64> {
  static uint64_t FetchPC(RISCVState *st) {
    return st->pc.qword;
  }

  static void SetPC(RISCVState *st, uint64_t pc) {
    st->pc.qword = pc;
  }
};

template <remill::ArchName kArch>
inline void ExecuteOne(test_runner::LiftingTester &lifter,
                       std::string_view name, std::string bytes,
                       uint64_t addr, RISCVState *st,
                       test_runner::MemoryHandler *mem) {
  auto maybe = lifter.LiftInstructionFunction(name, bytes, addr);
  ASSERT_TRUE(maybe.has_value());

  auto *lifted_func = maybe->first;
  const auto &insn = maybe->second;

  auto optimized_mod = llvm::CloneModule(*lifted_func->getParent());
  remill::OptimizeBareModule(optimized_mod.get());

  auto just_func_mod =
      std::make_unique<llvm::Module>("", optimized_mod->getContext());
  auto *func = test_runner::CopyFunctionIntoNewModule(
      just_func_mod.get(), lifted_func, optimized_mod);

  test_runner::ExecuteLiftedFunction<RISCVState, test_runner::MemoryHandler>(
      func, insn.bytes.size(), st, mem,
      [](RISCVState *s) { return ArchTraits<kArch>::FetchPC(s); });
}

}  // namespace riscv::test

