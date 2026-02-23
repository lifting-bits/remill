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

TEST(RISCV64, Mulhsu_SignedTimesUnsignedUpperBits) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t addr = 0x3000;

  // mulhsu x3, x1, x2  (signed(-1) * unsigned(2) => upper 64 = 0xFFFF...FFFF)
  const auto mulhsu_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/3, /*funct3=*/0x2, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr, riscv::Bytes32(mulhsu_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(addr)},
         {"x1", uint64_t(static_cast<uint64_t>(-1))},
         {"x2", uint64_t(2)}},
        {{"pc", uint64_t(addr + 4)},
         {"x3", uint64_t(0xFFFF'FFFF'FFFF'FFFFULL)}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }

  // mulhsu x4, x1, x2  (signed(0x7FFF...FFFF) * unsigned(4) => upper 64 = 1)
  // 0x7FFFFFFFFFFFFFFF * 4 = 0x1_FFFFFFFFFFFFFFFC => upper 64 = 1
  const auto mulhsu_word2 =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/4, /*funct3=*/0x2, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr + 4, riscv::Bytes32(mulhsu_word2),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(addr + 4)},
         {"x1", uint64_t(0x7FFF'FFFF'FFFF'FFFFULL)},
         {"x2", uint64_t(4)}},
        {{"pc", uint64_t(addr + 8)},
         {"x4", uint64_t(1)}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV64, Mulhu_UnsignedTimesUnsignedUpperBits) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t addr = 0x4000;

  // mulhu x3, x1, x2  (0xFFFF...FFFF * 2 => upper 64 = 1)
  // 0xFFFFFFFFFFFFFFFF * 2 = 0x1_FFFFFFFFFFFFFFFE => upper 64 = 1
  const auto mulhu_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/3, /*funct3=*/0x3, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr, riscv::Bytes32(mulhu_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(addr)},
         {"x1", uint64_t(0xFFFF'FFFF'FFFF'FFFFULL)},
         {"x2", uint64_t(2)}},
        {{"pc", uint64_t(addr + 4)},
         {"x3", uint64_t(1)}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }

  // mulhu x4, x1, x2  (0x8000...0000 * 0x8000...0000)
  // => upper 64 = 0x4000000000000000
  const auto mulhu_word2 =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/4, /*funct3=*/0x3, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr + 4, riscv::Bytes32(mulhu_word2),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(addr + 4)},
         {"x1", uint64_t(0x8000'0000'0000'0000ULL)},
         {"x2", uint64_t(0x8000'0000'0000'0000ULL)}},
        {{"pc", uint64_t(addr + 8)},
         {"x4", uint64_t(0x4000'0000'0000'0000ULL)}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV64, Mulw_Low32BitsSignExtended) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t addr = 0x5000;

  // mulw x3, x1, x2  (7 * 9 = 63, sign-extended)
  const auto mulw_word =
      riscv::EncodeR(riscv::kOpcodeOp32, /*rd=*/3, /*funct3=*/0x0, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr, riscv::Bytes32(mulw_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(addr)},
         {"x1", uint64_t(7)},
         {"x2", uint64_t(9)}},
        {{"pc", uint64_t(addr + 4)},
         {"x3", uint64_t(63)}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }

  // mulw x4, x1, x2  (0x40000000 * 3 = 0xC0000000, sign-extended)
  // Low 32 bits = 0xC0000000 (bit 31 set), sign-extends to 0xFFFFFFFF_C0000000
  const auto mulw_word2 =
      riscv::EncodeR(riscv::kOpcodeOp32, /*rd=*/4, /*funct3=*/0x0, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr + 4, riscv::Bytes32(mulw_word2),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(addr + 4)},
         {"x1", uint64_t(0x4000'0000ULL)},
         {"x2", uint64_t(3)}},
        {{"pc", uint64_t(addr + 8)},
         {"x4", uint64_t(0xFFFF'FFFF'C000'0000ULL)}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV64, Divw_SignedDivisionWord) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t addr = 0x6000;

  // divw x3, x1, x2  (-7 / 2 = -3, sign-extended)
  // rs1 low 32 bits = 0xFFFFFFF9 (i.e. -7 as int32)
  const auto divw_word =
      riscv::EncodeR(riscv::kOpcodeOp32, /*rd=*/3, /*funct3=*/0x4, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr, riscv::Bytes32(divw_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(addr)},
         {"x1", uint64_t(static_cast<uint64_t>(static_cast<int64_t>(-7)))},
         {"x2", uint64_t(2)}},
        {{"pc", uint64_t(addr + 4)},
         {"x3", uint64_t(static_cast<uint64_t>(static_cast<int64_t>(-3)))}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV64, Divuw_UnsignedDivisionWord) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t addr = 0x7000;

  // divuw x3, x1, x2  (7 / 2 = 3, sign-extended)
  const auto divuw_word =
      riscv::EncodeR(riscv::kOpcodeOp32, /*rd=*/3, /*funct3=*/0x5, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr, riscv::Bytes32(divuw_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(addr)},
         {"x1", uint64_t(7)},
         {"x2", uint64_t(2)}},
        {{"pc", uint64_t(addr + 4)},
         {"x3", uint64_t(3)}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }

  // divuw x4, x1, x2  (0xFFFFFFF9 / 2 = 0x7FFFFFFC, no sign-extension needed)
  // 0xFFFFFFF9 unsigned = 4294967289, / 2 = 2147483644 = 0x7FFFFFFC
  const auto divuw_word2 =
      riscv::EncodeR(riscv::kOpcodeOp32, /*rd=*/4, /*funct3=*/0x5, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr + 4, riscv::Bytes32(divuw_word2),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(addr + 4)},
         {"x1", uint64_t(0xFFFF'FFF9ULL)},
         {"x2", uint64_t(2)}},
        {{"pc", uint64_t(addr + 8)},
         {"x4", uint64_t(0x7FFF'FFFCULL)}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV64, Remw_SignedRemainderWord) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t addr = 0x8000;

  // remw x3, x1, x2  (-7 % 2 = -1, sign-extended)
  const auto remw_word =
      riscv::EncodeR(riscv::kOpcodeOp32, /*rd=*/3, /*funct3=*/0x6, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr, riscv::Bytes32(remw_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(addr)},
         {"x1", uint64_t(static_cast<uint64_t>(static_cast<int64_t>(-7)))},
         {"x2", uint64_t(2)}},
        {{"pc", uint64_t(addr + 4)},
         {"x3", uint64_t(static_cast<uint64_t>(static_cast<int64_t>(-1)))}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV64, Remuw_UnsignedRemainderWord) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t addr = 0x9000;

  // remuw x3, x1, x2  (7 % 2 = 1, sign-extended)
  const auto remuw_word =
      riscv::EncodeR(riscv::kOpcodeOp32, /*rd=*/3, /*funct3=*/0x7, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr, riscv::Bytes32(remuw_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(addr)},
         {"x1", uint64_t(7)},
         {"x2", uint64_t(2)}},
        {{"pc", uint64_t(addr + 4)},
         {"x3", uint64_t(1)}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }

  // remuw x4, x1, x2  (0xFFFFFFF9 % 4 = 1)
  // 0xFFFFFFF9 unsigned = 4294967289, % 4 = 1
  const auto remuw_word2 =
      riscv::EncodeR(riscv::kOpcodeOp32, /*rd=*/4, /*funct3=*/0x7, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr + 4, riscv::Bytes32(remuw_word2),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(addr + 4)},
         {"x1", uint64_t(0xFFFF'FFF9ULL)},
         {"x2", uint64_t(4)}},
        {{"pc", uint64_t(addr + 8)},
         {"x4", uint64_t(1)}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }
}
