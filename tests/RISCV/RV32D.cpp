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

using riscv::BitsFromDouble;
using riscv::BitsFromFloat;

TEST(RISCV32, FaddD_Basic) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fadd.d f3, f1, f2, rm=RNE(0)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3, /*funct3=*/0,
                                   /*rs1=*/1, /*rs2=*/2, /*funct7=*/0x1);

  // FPR accessors return qword for both RV32 and RV64
  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromDouble(1.5))},
       {"f2", uint64_t(BitsFromDouble(2.25))}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromDouble(1.5 + 2.25))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FldAndFsd_RoundTrip) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t load_addr = 0x7000;
  const uint64_t store_addr = 0x8000;
  const uint64_t val_bits = BitsFromDouble(1.25);

  // fld f1, 0(x10)
  const auto fld =
      riscv::EncodeI(riscv::kOpcodeLoadFp, /*rd=*/1, /*funct3=*/0x3,
                     /*rs1=*/10, /*imm12=*/0);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x2000, riscv::Bytes32(fld),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(0x2000u)},
         {"x10", uint32_t(load_addr)}},
        {{"pc", uint32_t(0x2004u)},
         {"f1", uint64_t(val_bits)}},
        kRV32RegAccessors);
    spec.AddPrecWrite<uint64_t>(load_addr, val_bits);
    runner.RunTestSpec(spec);
  }

  // fsd f1, 0(x11)
  const auto fsd =
      riscv::EncodeS(riscv::kOpcodeStoreFp, /*funct3=*/0x3, /*rs1=*/11,
                     /*rs2=*/1, /*imm12=*/0);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x2004, riscv::Bytes32(fsd),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(0x2004u)},
         {"x11", uint32_t(store_addr)},
         {"f1", uint64_t(val_bits)}},
        {{"pc", uint32_t(0x2008u)}},
        kRV32RegAccessors);
    spec.AddPostRead<uint64_t>(store_addr, val_bits);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV32, FsubD_Basic) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fsub.d f3, f1, f2, rm=RNE(0)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3,
                                   /*funct3=*/0, /*rs1=*/1, /*rs2=*/2,
                                   /*funct7=*/0x5);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromDouble(3.0))},
       {"f2", uint64_t(BitsFromDouble(1.0))}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromDouble(3.0 - 1.0))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FmulD_Basic) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fmul.d f3, f1, f2, rm=RNE(0)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3,
                                   /*funct3=*/0, /*rs1=*/1, /*rs2=*/2,
                                   /*funct7=*/0x9);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromDouble(2.0))},
       {"f2", uint64_t(BitsFromDouble(3.0))}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromDouble(2.0 * 3.0))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FeqD_Equal) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // feq.d x5, f1, f2  (funct7=0x51, funct3=0x2)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/5,
                                   /*funct3=*/0x2, /*rs1=*/1, /*rs2=*/2,
                                   /*funct7=*/0x51);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromDouble(1.0))},
       {"f2", uint64_t(BitsFromDouble(1.0))}},
      {{"pc", uint32_t(0x1004u)},
       {"x5", uint32_t(1u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FeqD_NotEqual) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // feq.d x5, f1, f2  (funct7=0x51, funct3=0x2)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/5,
                                   /*funct3=*/0x2, /*rs1=*/1, /*rs2=*/2,
                                   /*funct7=*/0x51);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromDouble(1.0))},
       {"f2", uint64_t(BitsFromDouble(2.0))}},
      {{"pc", uint32_t(0x1004u)},
       {"x5", uint32_t(0u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FltD_LessThan) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // flt.d x5, f1, f2  (funct7=0x51, funct3=0x1)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/5,
                                   /*funct3=*/0x1, /*rs1=*/1, /*rs2=*/2,
                                   /*funct7=*/0x51);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromDouble(1.0))},
       {"f2", uint64_t(BitsFromDouble(2.0))}},
      {{"pc", uint32_t(0x1004u)},
       {"x5", uint32_t(1u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FltD_NotLessThan) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // flt.d x5, f1, f2  (funct7=0x51, funct3=0x1)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/5,
                                   /*funct3=*/0x1, /*rs1=*/1, /*rs2=*/2,
                                   /*funct7=*/0x51);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromDouble(2.0))},
       {"f2", uint64_t(BitsFromDouble(1.0))}},
      {{"pc", uint32_t(0x1004u)},
       {"x5", uint32_t(0u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FleD_LessOrEqual) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fle.d x5, f1, f2  (funct7=0x51, funct3=0x0)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/5,
                                   /*funct3=*/0x0, /*rs1=*/1, /*rs2=*/2,
                                   /*funct7=*/0x51);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromDouble(1.0))},
       {"f2", uint64_t(BitsFromDouble(1.0))}},
      {{"pc", uint32_t(0x1004u)},
       {"x5", uint32_t(1u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FleD_GreaterThan) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fle.d x5, f1, f2  (funct7=0x51, funct3=0x0)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/5,
                                   /*funct3=*/0x0, /*rs1=*/1, /*rs2=*/2,
                                   /*funct7=*/0x51);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromDouble(3.0))},
       {"f2", uint64_t(BitsFromDouble(1.0))}},
      {{"pc", uint32_t(0x1004u)},
       {"x5", uint32_t(0u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FdivD_BasicDivision) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fdiv.d f3, f1, f2, rm=RNE(0)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3,
                                   /*funct3=*/0, /*rs1=*/1, /*rs2=*/2,
                                   /*funct7=*/0x0D);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromDouble(6.0))},
       {"f2", uint64_t(BitsFromDouble(2.0))}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromDouble(3.0))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FsqrtD_SquareRoot) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fsqrt.d f3, f1, rm=RNE(0)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3,
                                   /*funct3=*/0, /*rs1=*/1, /*rs2=*/0,
                                   /*funct7=*/0x2D);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromDouble(9.0))}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromDouble(3.0))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FsgnjD_CopySign) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fsgnj.d f3, f1, f2  (funct7=0x11, funct3=0)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3,
                                   /*funct3=*/0, /*rs1=*/1, /*rs2=*/2,
                                   /*funct7=*/0x11);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromDouble(-2.5))},
       {"f2", uint64_t(BitsFromDouble(1.0))}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromDouble(2.5))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FsgnjnD_NegateSign) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fsgnjn.d f3, f1, f2  (funct7=0x11, funct3=1)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3,
                                   /*funct3=*/1, /*rs1=*/1, /*rs2=*/2,
                                   /*funct7=*/0x11);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromDouble(2.5))},
       {"f2", uint64_t(BitsFromDouble(1.0))}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromDouble(-2.5))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FsgnjxD_XorSign) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fsgnjx.d f3, f1, f2  (funct7=0x11, funct3=2)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3,
                                   /*funct3=*/2, /*rs1=*/1, /*rs2=*/2,
                                   /*funct7=*/0x11);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromDouble(-2.5))},
       {"f2", uint64_t(BitsFromDouble(-1.0))}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromDouble(2.5))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FminD_Minimum) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fmin.d f3, f1, f2  (funct7=0x15, funct3=0)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3,
                                   /*funct3=*/0, /*rs1=*/1, /*rs2=*/2,
                                   /*funct7=*/0x15);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromDouble(1.5))},
       {"f2", uint64_t(BitsFromDouble(2.5))}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromDouble(1.5))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FmaxD_Maximum) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fmax.d f3, f1, f2  (funct7=0x15, funct3=1)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3,
                                   /*funct3=*/1, /*rs1=*/1, /*rs2=*/2,
                                   /*funct7=*/0x15);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromDouble(1.5))},
       {"f2", uint64_t(BitsFromDouble(2.5))}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromDouble(2.5))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FcvtSD_DoubleToSingle) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fcvt.s.d f3, f1, rm=RNE(0)  (funct7=0x20, rs2=1)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3,
                                   /*funct3=*/0, /*rs1=*/1, /*rs2=*/1,
                                   /*funct7=*/0x20);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromDouble(1.5))}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromFloat(1.5f))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FcvtDS_SingleToDouble) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fcvt.d.s f3, f1, rm=RNE(0)  (funct7=0x21, rs2=0)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3,
                                   /*funct3=*/0, /*rs1=*/1, /*rs2=*/0,
                                   /*funct7=*/0x21);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromFloat(1.5f))}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromDouble(1.5))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FcvtWD_DoubleToInt32) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fcvt.w.d x5, f1, rm=RNE(0)  (funct7=0x61, rs2=0)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/5,
                                   /*funct3=*/0, /*rs1=*/1, /*rs2=*/0,
                                   /*funct7=*/0x61);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromDouble(7.0))}},
      {{"pc", uint32_t(0x1004u)},
       {"x5", uint32_t(7u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FcvtWuD_DoubleToUint32) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fcvt.wu.d x5, f1, rm=RNE(0)  (funct7=0x61, rs2=1)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/5,
                                   /*funct3=*/0, /*rs1=*/1, /*rs2=*/1,
                                   /*funct7=*/0x61);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromDouble(7.0))}},
      {{"pc", uint32_t(0x1004u)},
       {"x5", uint32_t(7u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FcvtDW_Int32ToDouble) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fcvt.d.w f3, x5, rm=RNE(0)  (funct7=0x69, rs2=0)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3,
                                   /*funct3=*/0, /*rs1=*/5, /*rs2=*/0,
                                   /*funct7=*/0x69);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"x5", uint32_t(7u)}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromDouble(7.0))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FcvtDWu_Uint32ToDouble) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fcvt.d.wu f3, x5, rm=RNE(0)  (funct7=0x69, rs2=1)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3,
                                   /*funct3=*/0, /*rs1=*/5, /*rs2=*/1,
                                   /*funct7=*/0x69);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"x5", uint32_t(7u)}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromDouble(7.0))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FclassD_PositiveNormal) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fclass.d x5, f1  (funct7=0x71, rs2=0, funct3=1)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/5,
                                   /*funct3=*/1, /*rs1=*/1, /*rs2=*/0,
                                   /*funct7=*/0x71);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromDouble(1.0))}},
      {{"pc", uint32_t(0x1004u)},
       {"x5", uint32_t(uint32_t(1) << 6)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FmaddD_FusedMultiplyAdd) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fmadd.d f4, f1, f2, f3, rm=RNE(0)
  const auto word = riscv::EncodeR4(riscv::kOpcodeMadd, /*rd=*/4,
                                    /*rm=*/0, /*rs1=*/1, /*rs2=*/2,
                                    /*rs3=*/3, /*fmt=*/1);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromDouble(2.0))},
       {"f2", uint64_t(BitsFromDouble(3.0))},
       {"f3", uint64_t(BitsFromDouble(1.0))}},
      {{"pc", uint32_t(0x1004u)},
       {"f4", uint64_t(BitsFromDouble(7.0))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FmsubD_FusedMultiplySub) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fmsub.d f4, f1, f2, f3, rm=RNE(0)
  const auto word = riscv::EncodeR4(riscv::kOpcodeMsub, /*rd=*/4,
                                    /*rm=*/0, /*rs1=*/1, /*rs2=*/2,
                                    /*rs3=*/3, /*fmt=*/1);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromDouble(2.0))},
       {"f2", uint64_t(BitsFromDouble(3.0))},
       {"f3", uint64_t(BitsFromDouble(1.0))}},
      {{"pc", uint32_t(0x1004u)},
       {"f4", uint64_t(BitsFromDouble(5.0))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FnmsubD_NegFusedMultiplySub) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fnmsub.d f4, f1, f2, f3, rm=RNE(0)
  const auto word = riscv::EncodeR4(riscv::kOpcodeNmsub, /*rd=*/4,
                                    /*rm=*/0, /*rs1=*/1, /*rs2=*/2,
                                    /*rs3=*/3, /*fmt=*/1);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromDouble(2.0))},
       {"f2", uint64_t(BitsFromDouble(3.0))},
       {"f3", uint64_t(BitsFromDouble(1.0))}},
      {{"pc", uint32_t(0x1004u)},
       {"f4", uint64_t(BitsFromDouble(-5.0))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FnmaddD_NegFusedMultiplyAdd) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fnmadd.d f4, f1, f2, f3, rm=RNE(0)
  const auto word = riscv::EncodeR4(riscv::kOpcodeNmadd, /*rd=*/4,
                                    /*rm=*/0, /*rs1=*/1, /*rs2=*/2,
                                    /*rs3=*/3, /*fmt=*/1);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromDouble(2.0))},
       {"f2", uint64_t(BitsFromDouble(3.0))},
       {"f3", uint64_t(BitsFromDouble(1.0))}},
      {{"pc", uint32_t(0x1004u)},
       {"f4", uint64_t(BitsFromDouble(-7.0))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

