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

// RV64 register accessor map: GPR/PC via .qword, FPR via .qword
const static std::unordered_map<
    std::string,
    std::function<test_runner::RegisterValueRef(RISCVState &)>>
    kRV64RegAccessors = {
        {"pc",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.pc.qword;
         }},
        {"x0",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x0.qword;
         }},
        {"x1",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x1.qword;
         }},
        {"x2",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x2.qword;
         }},
        {"x3",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x3.qword;
         }},
        {"x4",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x4.qword;
         }},
        {"x5",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x5.qword;
         }},
        {"x6",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x6.qword;
         }},
        {"x7",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x7.qword;
         }},
        {"x8",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x8.qword;
         }},
        {"x9",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x9.qword;
         }},
        {"x10",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x10.qword;
         }},
        {"x11",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x11.qword;
         }},
        {"x12",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x12.qword;
         }},
        {"x13",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x13.qword;
         }},
        {"x14",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x14.qword;
         }},
        {"x15",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x15.qword;
         }},
        {"x16",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x16.qword;
         }},
        {"x17",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x17.qword;
         }},
        {"x18",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x18.qword;
         }},
        {"x19",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x19.qword;
         }},
        {"x20",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x20.qword;
         }},
        {"x21",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x21.qword;
         }},
        {"x22",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x22.qword;
         }},
        {"x23",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x23.qword;
         }},
        {"x24",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x24.qword;
         }},
        {"x25",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x25.qword;
         }},
        {"x26",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x26.qword;
         }},
        {"x27",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x27.qword;
         }},
        {"x28",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x28.qword;
         }},
        {"x29",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x29.qword;
         }},
        {"x30",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x30.qword;
         }},
        {"x31",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x31.qword;
         }},
        {"f0",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f0.qword;
         }},
        {"f1",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f1.qword;
         }},
        {"f2",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f2.qword;
         }},
        {"f3",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f3.qword;
         }},
        {"f4",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f4.qword;
         }},
        {"f5",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f5.qword;
         }},
        {"f6",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f6.qword;
         }},
        {"f7",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f7.qword;
         }},
        {"f8",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f8.qword;
         }},
        {"f9",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f9.qword;
         }},
        {"f10",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f10.qword;
         }},
        {"f11",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f11.qword;
         }},
        {"f12",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f12.qword;
         }},
        {"f13",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f13.qword;
         }},
        {"f14",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f14.qword;
         }},
        {"f15",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f15.qword;
         }},
        {"f16",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f16.qword;
         }},
        {"f17",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f17.qword;
         }},
        {"f18",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f18.qword;
         }},
        {"f19",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f19.qword;
         }},
        {"f20",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f20.qword;
         }},
        {"f21",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f21.qword;
         }},
        {"f22",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f22.qword;
         }},
        {"f23",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f23.qword;
         }},
        {"f24",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f24.qword;
         }},
        {"f25",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f25.qword;
         }},
        {"f26",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f26.qword;
         }},
        {"f27",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f27.qword;
         }},
        {"f28",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f28.qword;
         }},
        {"f29",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f29.qword;
         }},
        {"f30",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f30.qword;
         }},
        {"f31",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f31.qword;
         }},
        {"fcsr",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fcsr.fcsr;
         }},
        {"frm",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fcsr.frm;
         }},
        {"fflags",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fcsr.fflags;
         }},
        {"reserve",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.reserve;
         }},
        {"reserve_length",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.reserve_length;
         }},
        {"reserve_address",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.reserve_address.qword;
         }},
};

// RV32 register accessor map: GPR/PC via .dword, FPR via .qword
const static std::unordered_map<
    std::string,
    std::function<test_runner::RegisterValueRef(RISCVState &)>>
    kRV32RegAccessors = {
        {"pc",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.pc.dword;
         }},
        {"x0",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x0.dword;
         }},
        {"x1",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x1.dword;
         }},
        {"x2",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x2.dword;
         }},
        {"x3",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x3.dword;
         }},
        {"x4",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x4.dword;
         }},
        {"x5",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x5.dword;
         }},
        {"x6",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x6.dword;
         }},
        {"x7",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x7.dword;
         }},
        {"x8",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x8.dword;
         }},
        {"x9",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x9.dword;
         }},
        {"x10",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x10.dword;
         }},
        {"x11",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x11.dword;
         }},
        {"x12",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x12.dword;
         }},
        {"x13",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x13.dword;
         }},
        {"x14",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x14.dword;
         }},
        {"x15",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x15.dword;
         }},
        {"x16",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x16.dword;
         }},
        {"x17",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x17.dword;
         }},
        {"x18",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x18.dword;
         }},
        {"x19",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x19.dword;
         }},
        {"x20",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x20.dword;
         }},
        {"x21",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x21.dword;
         }},
        {"x22",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x22.dword;
         }},
        {"x23",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x23.dword;
         }},
        {"x24",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x24.dword;
         }},
        {"x25",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x25.dword;
         }},
        {"x26",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x26.dword;
         }},
        {"x27",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x27.dword;
         }},
        {"x28",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x28.dword;
         }},
        {"x29",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x29.dword;
         }},
        {"x30",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x30.dword;
         }},
        {"x31",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.x31.dword;
         }},
        {"f0",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f0.qword;
         }},
        {"f1",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f1.qword;
         }},
        {"f2",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f2.qword;
         }},
        {"f3",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f3.qword;
         }},
        {"f4",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f4.qword;
         }},
        {"f5",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f5.qword;
         }},
        {"f6",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f6.qword;
         }},
        {"f7",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f7.qword;
         }},
        {"f8",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f8.qword;
         }},
        {"f9",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f9.qword;
         }},
        {"f10",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f10.qword;
         }},
        {"f11",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f11.qword;
         }},
        {"f12",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f12.qword;
         }},
        {"f13",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f13.qword;
         }},
        {"f14",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f14.qword;
         }},
        {"f15",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f15.qword;
         }},
        {"f16",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f16.qword;
         }},
        {"f17",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f17.qword;
         }},
        {"f18",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f18.qword;
         }},
        {"f19",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f19.qword;
         }},
        {"f20",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f20.qword;
         }},
        {"f21",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f21.qword;
         }},
        {"f22",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f22.qword;
         }},
        {"f23",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f23.qword;
         }},
        {"f24",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f24.qword;
         }},
        {"f25",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f25.qword;
         }},
        {"f26",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f26.qword;
         }},
        {"f27",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f27.qword;
         }},
        {"f28",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f28.qword;
         }},
        {"f29",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f29.qword;
         }},
        {"f30",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f30.qword;
         }},
        {"f31",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fpr.f31.qword;
         }},
        {"fcsr",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fcsr.fcsr;
         }},
        {"frm",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fcsr.frm;
         }},
        {"fflags",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.fcsr.fflags;
         }},
        {"reserve",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.reserve;
         }},
        {"reserve_length",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.reserve_length;
         }},
        {"reserve_address",
         [](RISCVState &st) -> test_runner::RegisterValueRef {
           return &st.reserve_address.dword;
         }},
};

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
