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

#include <gtest/gtest.h>
#include <llvm/IR/LLVMContext.h>
#include <remill/Arch/Instruction.h>
#include <remill/Arch/Name.h>

#include <cstdint>

#include "RISCVTestSpec.h"
#include "TestUtil.h"

TEST(RISCV64, MulAndMulh_Basic) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t addr = 0x1000;

  // mul x3, x1, x2  (7 * 9 = 63)
  const auto mul_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/3, /*funct3=*/0x0, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr, riscv::Bytes32(mul_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(addr)},
         {"x1", uint64_t(7)},
         {"x2", uint64_t(9)}},
        {{"pc", uint64_t(addr + 4)},
         {"x3", uint64_t(63)}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }

  // mulh x4, x1, x2  (-2^63 * 2 => high 64 bits = 0xFFFF...FFFF)
  const auto mulh_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/4, /*funct3=*/0x1, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr + 4, riscv::Bytes32(mulh_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(addr + 4)},
         {"x1", uint64_t(0x8000'0000'0000'0000ULL)},
         {"x2", uint64_t(2)}},
        {{"pc", uint64_t(addr + 8)},
         {"x4", uint64_t(0xFFFF'FFFF'FFFF'FFFFULL)}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV64, DivAndRem_Basic) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t addr = 0x2000;

  // div x3, x1, x2  (-7 / 2 = -3)
  const auto div_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/3, /*funct3=*/0x4, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr, riscv::Bytes32(div_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(addr)},
         {"x1", uint64_t(static_cast<uint64_t>(-7))},
         {"x2", uint64_t(2)}},
        {{"pc", uint64_t(addr + 4)},
         {"x3", uint64_t(static_cast<uint64_t>(-3))}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }

  // rem x4, x1, x2  (-7 % 2 = -1)
  const auto rem_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/4, /*funct3=*/0x6, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr + 4, riscv::Bytes32(rem_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(addr + 4)},
         {"x1", uint64_t(static_cast<uint64_t>(-7))},
         {"x2", uint64_t(2)}},
        {{"pc", uint64_t(addr + 8)},
         {"x4", uint64_t(static_cast<uint64_t>(-1))}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }
}
