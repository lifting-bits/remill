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

TEST(RISCV32, MulAndMulh_Basic) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t addr = 0x1000;

  // mul x3, x1, x2  (7 * 9 = 63)
  const auto mul_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/3, /*funct3=*/0x0, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr, riscv::Bytes32(mul_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(addr)},
         {"x1", uint32_t(7)},
         {"x2", uint32_t(9)}},
        {{"pc", uint32_t(addr + 4)},
         {"x3", uint32_t(63)}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }

  // mulh x4, x1, x2  (-2^31 * 2 => high 32 bits = 0xFFFFFFFF)
  const auto mulh_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/4, /*funct3=*/0x1, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr + 4, riscv::Bytes32(mulh_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(addr + 4)},
         {"x1", uint32_t(0x8000'0000u)},
         {"x2", uint32_t(2)}},
        {{"pc", uint32_t(addr + 8)},
         {"x4", uint32_t(0xFFFF'FFFFu)}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV32, DivAndRem_Basic) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t addr = 0x2000;

  // div x3, x1, x2  (-7 / 2 = -3)
  const auto div_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/3, /*funct3=*/0x4, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr, riscv::Bytes32(div_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(addr)},
         {"x1", uint32_t(static_cast<uint32_t>(-7))},
         {"x2", uint32_t(2)}},
        {{"pc", uint32_t(addr + 4)},
         {"x3", uint32_t(static_cast<uint32_t>(-3))}},
        kRV32RegAccessors);
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
        {{"pc", uint32_t(addr + 4)},
         {"x1", uint32_t(static_cast<uint32_t>(-7))},
         {"x2", uint32_t(2)}},
        {{"pc", uint32_t(addr + 8)},
         {"x4", uint32_t(static_cast<uint32_t>(-1))}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV32, Mulhsu_SignedTimesUnsignedUpperBits) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t addr = 0x3000;

  // mulhsu x3, x1, x2  (signed(-1) * unsigned(2) => upper 32 = 0xFFFFFFFF)
  const auto mulhsu_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/3, /*funct3=*/0x2, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr, riscv::Bytes32(mulhsu_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(addr)},
         {"x1", uint32_t(static_cast<uint32_t>(-1))},
         {"x2", uint32_t(2)}},
        {{"pc", uint32_t(addr + 4)},
         {"x3", uint32_t(0xFFFF'FFFFu)}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }

  // mulhsu x4, x1, x2  (signed(0x7FFFFFFF) * unsigned(4) => upper 32 = 1)
  // 0x7FFFFFFF * 4 = 0x1_FFFFFFFC => upper 32 = 0x00000001
  const auto mulhsu_word2 =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/4, /*funct3=*/0x2, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr + 4, riscv::Bytes32(mulhsu_word2),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(addr + 4)},
         {"x1", uint32_t(0x7FFF'FFFFu)},
         {"x2", uint32_t(4)}},
        {{"pc", uint32_t(addr + 8)},
         {"x4", uint32_t(1)}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV32, Mulhu_UnsignedTimesUnsignedUpperBits) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t addr = 0x4000;

  // mulhu x3, x1, x2  (0xFFFFFFFF * 2 => upper 32 = 1)
  // 0xFFFFFFFF * 2 = 0x1_FFFFFFFE => upper 32 = 0x00000001
  const auto mulhu_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/3, /*funct3=*/0x3, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr, riscv::Bytes32(mulhu_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(addr)},
         {"x1", uint32_t(0xFFFF'FFFFu)},
         {"x2", uint32_t(2)}},
        {{"pc", uint32_t(addr + 4)},
         {"x3", uint32_t(1)}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }

  // mulhu x4, x1, x2  (0x80000000 * 0x80000000 => upper 32 = 0x40000000)
  // 0x80000000 * 0x80000000 = 0x40000000_00000000
  const auto mulhu_word2 =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/4, /*funct3=*/0x3, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr + 4, riscv::Bytes32(mulhu_word2),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(addr + 4)},
         {"x1", uint32_t(0x8000'0000u)},
         {"x2", uint32_t(0x8000'0000u)}},
        {{"pc", uint32_t(addr + 8)},
         {"x4", uint32_t(0x4000'0000u)}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }
}
