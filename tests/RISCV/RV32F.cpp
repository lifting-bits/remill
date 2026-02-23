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

using riscv::BitsFromFloat;

TEST(RISCV32, FaddS_WritesLow32BitsAndZeroExtends) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fadd.s f3, f1, f2, rm=RNE(0)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3, /*funct3=*/0,
                                   /*rs1=*/1, /*rs2=*/2, /*funct7=*/0x0);

  // FPR accessors return qword for both RV32 and RV64
  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromFloat(1.5f))},
       {"f2", uint64_t(BitsFromFloat(2.25f))}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromFloat(1.5f + 2.25f))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FsubS_BasicSubtraction) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fsub.s f3, f1, f2, rm=RNE(0)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3, /*funct3=*/0,
                                   /*rs1=*/1, /*rs2=*/2, /*funct7=*/0x04);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromFloat(3.5f))},
       {"f2", uint64_t(BitsFromFloat(1.25f))}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromFloat(3.5f - 1.25f))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FmulS_BasicMultiplication) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fmul.s f3, f1, f2, rm=RNE(0)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3, /*funct3=*/0,
                                   /*rs1=*/1, /*rs2=*/2, /*funct7=*/0x08);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromFloat(2.0f))},
       {"f2", uint64_t(BitsFromFloat(3.0f))}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromFloat(2.0f * 3.0f))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FeqS_EqualOperands) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // feq.s x5, f1, f2 (funct7=0x50, funct3=0x2)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/5, /*funct3=*/2,
                                   /*rs1=*/1, /*rs2=*/2, /*funct7=*/0x50);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromFloat(1.5f))},
       {"f2", uint64_t(BitsFromFloat(1.5f))}},
      {{"pc", uint32_t(0x1004u)},
       {"x5", uint32_t(1u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FeqS_UnequalOperands) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // feq.s x5, f1, f2 (funct7=0x50, funct3=0x2)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/5, /*funct3=*/2,
                                   /*rs1=*/1, /*rs2=*/2, /*funct7=*/0x50);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromFloat(1.0f))},
       {"f2", uint64_t(BitsFromFloat(2.0f))}},
      {{"pc", uint32_t(0x1004u)},
       {"x5", uint32_t(0u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FltS_LessThan) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // flt.s x5, f1, f2 (funct7=0x50, funct3=0x1)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/5, /*funct3=*/1,
                                   /*rs1=*/1, /*rs2=*/2, /*funct7=*/0x50);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromFloat(1.0f))},
       {"f2", uint64_t(BitsFromFloat(2.0f))}},
      {{"pc", uint32_t(0x1004u)},
       {"x5", uint32_t(1u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FltS_NotLessThan) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // flt.s x5, f1, f2 (funct7=0x50, funct3=0x1)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/5, /*funct3=*/1,
                                   /*rs1=*/1, /*rs2=*/2, /*funct7=*/0x50);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromFloat(2.0f))},
       {"f2", uint64_t(BitsFromFloat(1.0f))}},
      {{"pc", uint32_t(0x1004u)},
       {"x5", uint32_t(0u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FleS_LessOrEqual) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fle.s x5, f1, f2 (funct7=0x50, funct3=0x0)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/5, /*funct3=*/0,
                                   /*rs1=*/1, /*rs2=*/2, /*funct7=*/0x50);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromFloat(1.0f))},
       {"f2", uint64_t(BitsFromFloat(1.0f))}},
      {{"pc", uint32_t(0x1004u)},
       {"x5", uint32_t(1u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FmvWX_MovesIntegerBitsToFloatReg) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fmv.w.x f3, x5 (funct7=0x78, funct3=0x0, rs2=0)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3, /*funct3=*/0,
                                   /*rs1=*/5, /*rs2=*/0, /*funct7=*/0x78);

  const uint32_t float_bits = BitsFromFloat(2.5f);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"x5", uint32_t(float_bits)}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(float_bits)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FcvtSW_Int32ToFloat) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fcvt.s.w f3, x5, rm=RNE(0) (funct7=0x68, rs2=0)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3, /*funct3=*/0,
                                   /*rs1=*/5, /*rs2=*/0, /*funct7=*/0x68);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"x5", uint32_t(7u)}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromFloat(7.0f))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FdivS_BasicDivision) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fdiv.s f3, f1, f2, rm=RNE(0)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3, /*funct3=*/0,
                                   /*rs1=*/1, /*rs2=*/2, /*funct7=*/0x0C);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromFloat(6.0f))},
       {"f2", uint64_t(BitsFromFloat(2.0f))}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromFloat(3.0f))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FsqrtS_SquareRoot) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fsqrt.s f3, f1, rm=RNE(0) (rs2=0)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3, /*funct3=*/0,
                                   /*rs1=*/1, /*rs2=*/0, /*funct7=*/0x2C);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromFloat(9.0f))}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromFloat(3.0f))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FsgnjS_CopiesSign) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fsgnj.s f3, f1, f2 (funct7=0x10, funct3=0)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3, /*funct3=*/0,
                                   /*rs1=*/1, /*rs2=*/2, /*funct7=*/0x10);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromFloat(-2.5f))},
       {"f2", uint64_t(BitsFromFloat(1.0f))}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromFloat(2.5f))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FsgnjnS_CopiesNegatedSign) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fsgnjn.s f3, f1, f2 (funct7=0x10, funct3=1)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3, /*funct3=*/1,
                                   /*rs1=*/1, /*rs2=*/2, /*funct7=*/0x10);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromFloat(2.5f))},
       {"f2", uint64_t(BitsFromFloat(1.0f))}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromFloat(-2.5f))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FsgnjxS_XorsSign) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fsgnjx.s f3, f1, f2 (funct7=0x10, funct3=2)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3, /*funct3=*/2,
                                   /*rs1=*/1, /*rs2=*/2, /*funct7=*/0x10);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromFloat(-2.5f))},
       {"f2", uint64_t(BitsFromFloat(-1.0f))}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromFloat(2.5f))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FminS_ReturnsMinimum) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fmin.s f3, f1, f2 (funct7=0x14, funct3=0)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3, /*funct3=*/0,
                                   /*rs1=*/1, /*rs2=*/2, /*funct7=*/0x14);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromFloat(1.5f))},
       {"f2", uint64_t(BitsFromFloat(2.5f))}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromFloat(1.5f))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FmaxS_ReturnsMaximum) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fmax.s f3, f1, f2 (funct7=0x14, funct3=1)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3, /*funct3=*/1,
                                   /*rs1=*/1, /*rs2=*/2, /*funct7=*/0x14);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromFloat(1.5f))},
       {"f2", uint64_t(BitsFromFloat(2.5f))}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromFloat(2.5f))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FmvXW_MovesFloatBitsToIntegerReg) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fmv.x.w x5, f1 (funct7=0x70, rs2=0, funct3=0)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/5, /*funct3=*/0,
                                   /*rs1=*/1, /*rs2=*/0, /*funct7=*/0x70);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromFloat(2.5f))}},
      {{"pc", uint32_t(0x1004u)},
       {"x5", uint32_t(BitsFromFloat(2.5f))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FcvtWS_FloatToInt32) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fcvt.w.s x5, f1, rm=RNE(0) (funct7=0x60, rs2=0)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/5, /*funct3=*/0,
                                   /*rs1=*/1, /*rs2=*/0, /*funct7=*/0x60);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromFloat(7.0f))}},
      {{"pc", uint32_t(0x1004u)},
       {"x5", uint32_t(7u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FcvtWuS_FloatToUInt32) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fcvt.wu.s x5, f1, rm=RNE(0) (funct7=0x60, rs2=1)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/5, /*funct3=*/0,
                                   /*rs1=*/1, /*rs2=*/1, /*funct7=*/0x60);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromFloat(7.0f))}},
      {{"pc", uint32_t(0x1004u)},
       {"x5", uint32_t(7u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FcvtSWu_UInt32ToFloat) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fcvt.s.wu f3, x5, rm=RNE(0) (funct7=0x68, rs2=1)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3, /*funct3=*/0,
                                   /*rs1=*/5, /*rs2=*/1, /*funct7=*/0x68);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"x5", uint32_t(7u)}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromFloat(7.0f))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

// DISABLED: fclass.s is unimplemented in Ghidra Sleigh spec (body is #TODO).
TEST(RISCV32, DISABLED_FclassS_PositiveNormal) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fclass.s x5, f1 (funct7=0x70, rs2=0, funct3=1)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/5, /*funct3=*/1,
                                   /*rs1=*/1, /*rs2=*/0, /*funct7=*/0x70);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromFloat(1.0f))}},
      {{"pc", uint32_t(0x1004u)},
       {"x5", uint32_t(1u << 6)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FmaddS_FusedMultiplyAdd) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fmadd.s f4, f1, f2, f3, rm=RNE(0)
  const auto word = riscv::EncodeR4(riscv::kOpcodeMadd, /*rd=*/4, /*rm=*/0,
                                    /*rs1=*/1, /*rs2=*/2, /*rs3=*/3, /*fmt=*/0);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromFloat(2.0f))},
       {"f2", uint64_t(BitsFromFloat(3.0f))},
       {"f3", uint64_t(BitsFromFloat(1.0f))}},
      {{"pc", uint32_t(0x1004u)},
       {"f4", uint64_t(BitsFromFloat(7.0f))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FmsubS_FusedMultiplySub) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fmsub.s f4, f1, f2, f3, rm=RNE(0)
  const auto word = riscv::EncodeR4(riscv::kOpcodeMsub, /*rd=*/4, /*rm=*/0,
                                    /*rs1=*/1, /*rs2=*/2, /*rs3=*/3, /*fmt=*/0);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromFloat(2.0f))},
       {"f2", uint64_t(BitsFromFloat(3.0f))},
       {"f3", uint64_t(BitsFromFloat(1.0f))}},
      {{"pc", uint32_t(0x1004u)},
       {"f4", uint64_t(BitsFromFloat(5.0f))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FnmsubS_NegFusedMultiplySub) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fnmsub.s f4, f1, f2, f3, rm=RNE(0)
  const auto word =
      riscv::EncodeR4(riscv::kOpcodeNmsub, /*rd=*/4, /*rm=*/0,
                      /*rs1=*/1, /*rs2=*/2, /*rs3=*/3, /*fmt=*/0);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromFloat(2.0f))},
       {"f2", uint64_t(BitsFromFloat(3.0f))},
       {"f3", uint64_t(BitsFromFloat(1.0f))}},
      {{"pc", uint32_t(0x1004u)},
       {"f4", uint64_t(BitsFromFloat(-5.0f))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FnmaddS_NegFusedMultiplyAdd) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fnmadd.s f4, f1, f2, f3, rm=RNE(0)
  const auto word =
      riscv::EncodeR4(riscv::kOpcodeNmadd, /*rd=*/4, /*rm=*/0,
                      /*rs1=*/1, /*rs2=*/2, /*rs3=*/3, /*fmt=*/0);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromFloat(2.0f))},
       {"f2", uint64_t(BitsFromFloat(3.0f))},
       {"f3", uint64_t(BitsFromFloat(1.0f))}},
      {{"pc", uint32_t(0x1004u)},
       {"f4", uint64_t(BitsFromFloat(-7.0f))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FlwAndFsw_RoundTrip) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t load_addr = 0x5000;
  const uint64_t store_addr = 0x6000;
  const uint32_t val_bits = BitsFromFloat(1.25f);

  // flw f1, 0(x10)
  const auto flw =
      riscv::EncodeI(riscv::kOpcodeLoadFp, /*rd=*/1, /*funct3=*/0x2,
                     /*rs1=*/10, /*imm12=*/0);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x2000, riscv::Bytes32(flw),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(0x2000u)},
         {"x10", uint32_t(load_addr)}},
        {{"pc", uint32_t(0x2004u)},
         {"f1", uint64_t(val_bits)}},
        kRV32RegAccessors);
    spec.AddPrecWrite<uint32_t>(load_addr, val_bits);
    runner.RunTestSpec(spec);
  }

  // fsw f1, 0(x11)
  const auto fsw =
      riscv::EncodeS(riscv::kOpcodeStoreFp, /*funct3=*/0x2, /*rs1=*/11,
                     /*rs2=*/1, /*imm12=*/0);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x2004, riscv::Bytes32(fsw),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(0x2004u)},
         {"x11", uint32_t(store_addr)},
         {"f1", uint64_t(val_bits)}},
        {{"pc", uint32_t(0x2008u)}},
        kRV32RegAccessors);
    spec.AddPostRead<uint32_t>(store_addr, val_bits);
    runner.RunTestSpec(spec);
  }
}
