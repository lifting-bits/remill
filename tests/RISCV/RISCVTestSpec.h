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

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <remill/Arch/Instruction.h>
#include <remill/Arch/Name.h>
#include <remill/BC/Optimizer.h>
#include <remill/OS/OS.h>
#include <test_runner/TestOutputSpec.h>
#include <test_runner/TestRunner.h>

#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>

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

// Zero volatile Sleigh copy fields in RISCVState.  Sleigh semantics may
// read wider regions of the state struct (e.g. 64-bit reads that span a
// volatile padding byte and the real field), so leftover random bytes in
// those padding slots corrupt the value seen by the lifted code.
inline void ZeroVolatileFields(RISCVState &st) {
  // Zero the entire FCSR struct.  Sleigh CSRRW on RV64 reads 64 bits
  // starting at the fcsr field, spanning into frm/fflags/padding.
  // Randomized bytes in any of these slots corrupt the value the
  // lifted code sees, so zero everything and let preconditions set
  // the fields that matter.
  std::memset(&st.fcsr, 0, sizeof(st.fcsr));

  // LR/SC reservation volatile copies.
  st._reserve_address = 0;
  st._reserve = 0;
  st._reserve_length = 0;

  // PC volatile copy.
  st._pc = 0;

  // Trailing struct padding.
  std::memset(st._padding, 0, sizeof(st._padding));
}

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

  test_runner::ExecuteLiftedFunction<RISCVState>(
      func, insn.bytes.size(), st, mem,
      [](RISCVState *s) { return ArchTraits<kArch>::FetchPC(s); });
}

}  // namespace riscv::test

// clang-format off

// Macros to generate register accessor map entries.  GPR and PC width
// varies between RV32 (.dword) and RV64 (.qword); FPR, FCSR, and
// reservation fields are identical in both maps.

#define RISCV_GPR_ACCESSOR(N, M) \
  {"x" #N, [](RISCVState &st) -> test_runner::RegisterValueRef { \
    return &st.gpr.x##N.M; \
  }}

#define RISCV_FPR_ACCESSOR(N) \
  {"f" #N, [](RISCVState &st) -> test_runner::RegisterValueRef { \
    return &st.fpr.f##N.qword; \
  }}

#define RISCV_GPR_ACCESSORS(M) \
  RISCV_GPR_ACCESSOR(0, M),  RISCV_GPR_ACCESSOR(1, M),  \
  RISCV_GPR_ACCESSOR(2, M),  RISCV_GPR_ACCESSOR(3, M),  \
  RISCV_GPR_ACCESSOR(4, M),  RISCV_GPR_ACCESSOR(5, M),  \
  RISCV_GPR_ACCESSOR(6, M),  RISCV_GPR_ACCESSOR(7, M),  \
  RISCV_GPR_ACCESSOR(8, M),  RISCV_GPR_ACCESSOR(9, M),  \
  RISCV_GPR_ACCESSOR(10, M), RISCV_GPR_ACCESSOR(11, M), \
  RISCV_GPR_ACCESSOR(12, M), RISCV_GPR_ACCESSOR(13, M), \
  RISCV_GPR_ACCESSOR(14, M), RISCV_GPR_ACCESSOR(15, M), \
  RISCV_GPR_ACCESSOR(16, M), RISCV_GPR_ACCESSOR(17, M), \
  RISCV_GPR_ACCESSOR(18, M), RISCV_GPR_ACCESSOR(19, M), \
  RISCV_GPR_ACCESSOR(20, M), RISCV_GPR_ACCESSOR(21, M), \
  RISCV_GPR_ACCESSOR(22, M), RISCV_GPR_ACCESSOR(23, M), \
  RISCV_GPR_ACCESSOR(24, M), RISCV_GPR_ACCESSOR(25, M), \
  RISCV_GPR_ACCESSOR(26, M), RISCV_GPR_ACCESSOR(27, M), \
  RISCV_GPR_ACCESSOR(28, M), RISCV_GPR_ACCESSOR(29, M), \
  RISCV_GPR_ACCESSOR(30, M), RISCV_GPR_ACCESSOR(31, M)

#define RISCV_FPR_ACCESSORS \
  RISCV_FPR_ACCESSOR(0),  RISCV_FPR_ACCESSOR(1),  \
  RISCV_FPR_ACCESSOR(2),  RISCV_FPR_ACCESSOR(3),  \
  RISCV_FPR_ACCESSOR(4),  RISCV_FPR_ACCESSOR(5),  \
  RISCV_FPR_ACCESSOR(6),  RISCV_FPR_ACCESSOR(7),  \
  RISCV_FPR_ACCESSOR(8),  RISCV_FPR_ACCESSOR(9),  \
  RISCV_FPR_ACCESSOR(10), RISCV_FPR_ACCESSOR(11), \
  RISCV_FPR_ACCESSOR(12), RISCV_FPR_ACCESSOR(13), \
  RISCV_FPR_ACCESSOR(14), RISCV_FPR_ACCESSOR(15), \
  RISCV_FPR_ACCESSOR(16), RISCV_FPR_ACCESSOR(17), \
  RISCV_FPR_ACCESSOR(18), RISCV_FPR_ACCESSOR(19), \
  RISCV_FPR_ACCESSOR(20), RISCV_FPR_ACCESSOR(21), \
  RISCV_FPR_ACCESSOR(22), RISCV_FPR_ACCESSOR(23), \
  RISCV_FPR_ACCESSOR(24), RISCV_FPR_ACCESSOR(25), \
  RISCV_FPR_ACCESSOR(26), RISCV_FPR_ACCESSOR(27), \
  RISCV_FPR_ACCESSOR(28), RISCV_FPR_ACCESSOR(29), \
  RISCV_FPR_ACCESSOR(30), RISCV_FPR_ACCESSOR(31)

#define RISCV_SHARED_ACCESSORS \
  {"fcsr",           [](RISCVState &st) -> test_runner::RegisterValueRef { return &st.fcsr.fcsr; }},    \
  {"frm",            [](RISCVState &st) -> test_runner::RegisterValueRef { return &st.fcsr.frm; }},     \
  {"fflags",         [](RISCVState &st) -> test_runner::RegisterValueRef { return &st.fcsr.fflags; }},  \
  {"reserve",        [](RISCVState &st) -> test_runner::RegisterValueRef { return &st.reserve; }},      \
  {"reserve_length", [](RISCVState &st) -> test_runner::RegisterValueRef { return &st.reserve_length; }}

using RegAccessorMap = std::unordered_map<
    std::string,
    std::function<test_runner::RegisterValueRef(RISCVState &)>>;

const static RegAccessorMap kRV64RegAccessors = {
    {"pc", [](RISCVState &st) -> test_runner::RegisterValueRef { return &st.pc.qword; }},
    RISCV_GPR_ACCESSORS(qword),
    RISCV_FPR_ACCESSORS,
    RISCV_SHARED_ACCESSORS,
    {"reserve_address", [](RISCVState &st) -> test_runner::RegisterValueRef { return &st.reserve_address.qword; }},
};

const static RegAccessorMap kRV32RegAccessors = {
    {"pc", [](RISCVState &st) -> test_runner::RegisterValueRef { return &st.pc.dword; }},
    RISCV_GPR_ACCESSORS(dword),
    RISCV_FPR_ACCESSORS,
    RISCV_SHARED_ACCESSORS,
    {"reserve_address", [](RISCVState &st) -> test_runner::RegisterValueRef { return &st.reserve_address.dword; }},
};

#undef RISCV_GPR_ACCESSOR
#undef RISCV_FPR_ACCESSOR
#undef RISCV_GPR_ACCESSORS
#undef RISCV_FPR_ACCESSORS
#undef RISCV_SHARED_ACCESSORS

// clang-format on

// Test spec runner for RISC-V architectures
template <remill::ArchName kArch>
class RISCVTestSpecRunner {
 private:
  test_runner::LiftingTester lifter;
  uint64_t tst_ctr;
  test_runner::random_bytes_engine rbe;

 public:
  explicit RISCVTestSpecRunner(llvm::LLVMContext &context)
      : lifter(context, remill::OSName::kOSLinux, kArch), tst_ctr(0) {}

  test_runner::LiftingTester &GetLifter() {
    return lifter;
  }

  void RunTestSpec(
      const test_runner::TestOutputSpec<RISCVState> &test) {
    std::stringstream ss;
    ss << "test_disas_func_" << this->tst_ctr++;

    auto maybe_func = lifter.LiftInstructionFunction(
        ss.str(), test.target_bytes, test.addr);

    CHECK(maybe_func.has_value());
    auto lifted_func = maybe_func->first;

    auto new_mod = llvm::CloneModule(*lifted_func->getParent());
    remill::OptimizeBareModule(new_mod.get());

    auto just_func_mod =
        std::make_unique<llvm::Module>("", new_mod->getContext());

    auto new_func = test_runner::CopyFunctionIntoNewModule(
        just_func_mod.get(), lifted_func, new_mod);
    RISCVState st = {};

    test.CheckLiftedInstruction(maybe_func->second);
    test_runner::RandomizeState(st, this->rbe);
    riscv::test::ZeroVolatileFields(st);

    test.SetupTestPreconditions(st);
    auto mem_hand = std::make_unique<test_runner::MemoryHandler>(
        llvm::endianness::little);

    for (const auto &prec : test.GetMemoryPrecs()) {
      prec(*mem_hand);
    }

    test_runner::ExecuteLiftedFunction<RISCVState>(
        new_func, test.target_bytes.length(), &st, mem_hand.get(),
        [](RISCVState *s) {
          return riscv::test::ArchTraits<kArch>::FetchPC(s);
        });

    test.CheckResultingState(st);
    test.CheckResultingMemory(*mem_hand);
  }
};
