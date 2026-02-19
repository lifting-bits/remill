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

TEST(RISCV32, CompressedAddi_IncrementsPcBy2) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t addr = 0xD000;

  // c.addi x1, 1
  const auto half = riscv::EncodeCAddi(/*rd=*/1, /*imm6=*/1);

  test_runner::TestOutputSpec<RISCVState> spec(
      addr, riscv::Bytes16(half),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(addr)},
       {"x1", uint32_t(41)}},
      {{"pc", uint32_t(addr + 2)},
       {"x1", uint32_t(42)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedLwAndSw_Use2ByteInstructions) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t base = 0x5000;

  // c.lw x9, 12(x8)
  const auto clw = riscv::EncodeCLw(/*rd=*/9, /*rs1=*/8, /*uimm=*/12);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x1000, riscv::Bytes16(clw),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(0x1000u)},
         {"x8", uint32_t(base)}},
        {{"pc", uint32_t(0x1002u)},
         {"x9", uint32_t(0xDEADBEEFu)}},
        kRV32RegAccessors);
    spec.AddPrecWrite<uint32_t>(base + 12, 0xDEADBEEFu);
    runner.RunTestSpec(spec);
  }

  // c.sw x9, 16(x8)
  const uint32_t store_val = 0xA0B0C0D0u;
  const auto csw = riscv::EncodeCSw(/*rs2=*/9, /*rs1=*/8, /*uimm=*/16);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x1002, riscv::Bytes16(csw),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(0x1002u)},
         {"x8", uint32_t(base)},
         {"x9", uint32_t(store_val)}},
        {{"pc", uint32_t(0x1004u)}},
        kRV32RegAccessors);
    spec.AddPostRead<uint32_t>(base + 16, store_val);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV32, CompressedJ_JumpsRelative) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.j +8
  const auto halfword = riscv::EncodeCJ(/*imm12=*/8);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x2000, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryDirectJump,
      {{"pc", uint32_t(0x2000u)}},
      {{"pc", uint32_t(0x2008u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedBeqz_TakenAndNotTaken) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.beqz x8, +8
  const auto halfword = riscv::EncodeCBeqz(/*rs1=*/8, /*imm9=*/8);

  // Taken: x8 == 0
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x3000, riscv::Bytes16(halfword),
        remill::Instruction::Category::kCategoryConditionalBranch,
        {{"pc", uint32_t(0x3000u)},
         {"x8", uint32_t(0)}},
        {{"pc", uint32_t(0x3008u)}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }

  // Not taken: x8 != 0
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x3000, riscv::Bytes16(halfword),
        remill::Instruction::Category::kCategoryConditionalBranch,
        {{"pc", uint32_t(0x3000u)},
         {"x8", uint32_t(1)}},
        {{"pc", uint32_t(0x3002u)}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV32, CompressedBnez_TakenAndNotTaken) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.bnez x8, +8
  const auto halfword = riscv::EncodeCBnez(/*rs1=*/8, /*imm9=*/8);

  // Taken: x8 != 0
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x4000, riscv::Bytes16(halfword),
        remill::Instruction::Category::kCategoryConditionalBranch,
        {{"pc", uint32_t(0x4000u)},
         {"x8", uint32_t(1)}},
        {{"pc", uint32_t(0x4008u)}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }

  // Not taken: x8 == 0
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x4000, riscv::Bytes16(halfword),
        remill::Instruction::Category::kCategoryConditionalBranch,
        {{"pc", uint32_t(0x4000u)},
         {"x8", uint32_t(0)}},
        {{"pc", uint32_t(0x4002u)}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV32, CompressedJr_JumpsToRegister) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.jr x5
  const auto halfword = riscv::EncodeCJr(/*rs1=*/5);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x5000, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryIndirectJump,
      {{"pc", uint32_t(0x5000u)},
       {"x5", uint32_t(0x6000u)}},
      {{"pc", uint32_t(0x6000u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedJalr_LinksAndJumpsToRegister) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.jalr x5 => x1 = pc + 2, pc = x5
  const auto halfword = riscv::EncodeCJalr(/*rs1=*/5);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x5000, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryIndirectFunctionCall,
      {{"pc", uint32_t(0x5000u)},
       {"x5", uint32_t(0x7000u)}},
      {{"pc", uint32_t(0x7000u)},
       {"x1", uint32_t(0x5002u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedLi_LoadsImmediate) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.li x10, 15 => x10 = 15
  const auto halfword = riscv::EncodeCLi(/*rd=*/10, /*imm6=*/15);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x6000, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x6000u)}},
      {{"pc", uint32_t(0x6002u)},
       {"x10", uint32_t(15)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedLi_SignExtendsNegativeImmediate) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.li x10, -1 => x10 = 0xFFFFFFFF (sign-extended)
  const auto halfword = riscv::EncodeCLi(/*rd=*/10, /*imm6=*/-1);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x6000, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x6000u)}},
      {{"pc", uint32_t(0x6002u)},
       {"x10", uint32_t(0xFFFFFFFFu)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedMv_CopiesRegister) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.mv x10, x11 => x10 = x11
  const auto halfword = riscv::EncodeCMv(/*rd=*/10, /*rs2=*/11);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x7000, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x7000u)},
       {"x11", uint32_t(0xCAFEBABEu)}},
      {{"pc", uint32_t(0x7002u)},
       {"x10", uint32_t(0xCAFEBABEu)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedAdd_AddsRegisters) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.add x10, x11 => x10 = x10 + x11
  const auto halfword = riscv::EncodeCAdd(/*rd=*/10, /*rs2=*/11);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x8000, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x8000u)},
       {"x10", uint32_t(100)},
       {"x11", uint32_t(200)}},
      {{"pc", uint32_t(0x8002u)},
       {"x10", uint32_t(300)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedNop_AdvancesPcOnly) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.nop => no operation, just advance pc by 2
  const uint16_t halfword = 0x0001u;

  test_runner::TestOutputSpec<RISCVState> spec(
      0x9000, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x9000u)},
       {"x1", uint32_t(0xDEADBEEFu)}},
      {{"pc", uint32_t(0x9002u)},
       {"x1", uint32_t(0xDEADBEEFu)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedAddi4spn_AddsScaledImmToSp) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.addi4spn x8, 32 => x8 = x2 + 32
  const auto halfword = riscv::EncodeCAddi4spn(/*rd=*/8, /*nzuimm=*/32);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xA000, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0xA000u)},
       {"x2", uint32_t(0x1000u)}},
      {{"pc", uint32_t(0xA002u)},
       {"x8", uint32_t(0x1020u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedJal_LinksAndJumps) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.jal +8 => x1 = pc + 2, pc = pc + 8
  const auto halfword = riscv::EncodeCJal(/*imm12=*/8);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xA100, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryDirectFunctionCall,
      {{"pc", uint32_t(0xA100u)}},
      {{"pc", uint32_t(0xA108u)},
       {"x1", uint32_t(0xA102u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedAddi16sp_AddsScaledImmToSp) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.addi16sp 32 => x2 = x2 + 32
  const auto halfword = riscv::EncodeCAddi16sp(/*nzimm=*/32);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xA200, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0xA200u)},
       {"x2", uint32_t(0x1000u)}},
      {{"pc", uint32_t(0xA202u)},
       {"x2", uint32_t(0x1020u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedLui_LoadsUpperImmediate) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.lui x10, 1 => x10 = 1 << 12 = 0x1000
  const auto halfword = riscv::EncodeCLui(/*rd=*/10, /*nzimm=*/1);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xA300, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0xA300u)}},
      {{"pc", uint32_t(0xA302u)},
       {"x10", uint32_t(0x1000u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedSrli_ShiftsRightLogical) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.srli x8, 4 => x8 = x8 >> 4 (logical)
  const auto halfword = riscv::EncodeCSrli(/*rd=*/8, /*shamt=*/4);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xA400, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0xA400u)},
       {"x8", uint32_t(0xF0u)}},
      {{"pc", uint32_t(0xA402u)},
       {"x8", uint32_t(0x0Fu)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedSrai_ShiftsRightArithmetic) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.srai x8, 4 => x8 = x8 >> 4 (arithmetic)
  const auto halfword = riscv::EncodeCSrai(/*rd=*/8, /*shamt=*/4);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xA500, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0xA500u)},
       {"x8", uint32_t(0xFFFFFFF0u)}},
      {{"pc", uint32_t(0xA502u)},
       {"x8", uint32_t(0xFFFFFFFFu)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedAndi_AndsImmediate) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.andi x8, 0xF => x8 = x8 & 0xF
  const auto halfword = riscv::EncodeCAndi(/*rd=*/8, /*imm6=*/0xF);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xA600, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0xA600u)},
       {"x8", uint32_t(0xFFu)}},
      {{"pc", uint32_t(0xA602u)},
       {"x8", uint32_t(0x0Fu)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedSub_SubtractsRegisters) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.sub x8, x9 => x8 = x8 - x9
  const auto halfword = riscv::EncodeCSub(/*rd=*/8, /*rs2=*/9);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xA700, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0xA700u)},
       {"x8", uint32_t(10)},
       {"x9", uint32_t(3)}},
      {{"pc", uint32_t(0xA702u)},
       {"x8", uint32_t(7)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedXor_XorsRegisters) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.xor x8, x9 => x8 = x8 ^ x9
  const auto halfword = riscv::EncodeCXor(/*rd=*/8, /*rs2=*/9);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xA800, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0xA800u)},
       {"x8", uint32_t(0xFFu)},
       {"x9", uint32_t(0x0Fu)}},
      {{"pc", uint32_t(0xA802u)},
       {"x8", uint32_t(0xF0u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedOr_OrsRegisters) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.or x8, x9 => x8 = x8 | x9
  const auto halfword = riscv::EncodeCOr(/*rd=*/8, /*rs2=*/9);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xA900, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0xA900u)},
       {"x8", uint32_t(0xF0u)},
       {"x9", uint32_t(0x0Fu)}},
      {{"pc", uint32_t(0xA902u)},
       {"x8", uint32_t(0xFFu)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedAnd_AndsRegisters) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.and x8, x9 => x8 = x8 & x9
  const auto halfword = riscv::EncodeCAnd(/*rd=*/8, /*rs2=*/9);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xAA00, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0xAA00u)},
       {"x8", uint32_t(0xFFu)},
       {"x9", uint32_t(0x0Fu)}},
      {{"pc", uint32_t(0xAA02u)},
       {"x8", uint32_t(0x0Fu)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedSlli_ShiftsLeftLogical) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.slli x10, 4 => x10 = x10 << 4
  const auto halfword = riscv::EncodeCSlli(/*rd=*/10, /*shamt=*/4);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xAB00, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0xAB00u)},
       {"x10", uint32_t(0x0Fu)}},
      {{"pc", uint32_t(0xAB02u)},
       {"x10", uint32_t(0xF0u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedLwsp_LoadsWordFromSp) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.lwsp x10, 8 => x10 = mem[x2 + 8]
  const auto halfword = riscv::EncodeCLwsp(/*rd=*/10, /*uimm=*/8);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xAC00, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0xAC00u)},
       {"x2", uint32_t(0x5000u)}},
      {{"pc", uint32_t(0xAC02u)},
       {"x10", uint32_t(0xDEADBEEFu)}},
      kRV32RegAccessors);
  spec.AddPrecWrite<uint32_t>(0x5008, 0xDEADBEEFu);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedSwsp_StoresWordToSp) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.swsp x10, 12 => mem[x2 + 12] = x10
  const auto halfword = riscv::EncodeCSwsp(/*rs2=*/10, /*uimm=*/12);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xAD00, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0xAD00u)},
       {"x2", uint32_t(0x5000u)},
       {"x10", uint32_t(0xCAFEBABEu)}},
      {{"pc", uint32_t(0xAD02u)}},
      kRV32RegAccessors);
  spec.AddPostRead<uint32_t>(0x500C, 0xCAFEBABEu);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedEbreak_TriggersError) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.ebreak => raw encoding 0x9002
  const uint16_t halfword = 0x9002u;

  test_runner::TestOutputSpec<RISCVState> spec(
      0xAE00, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryError,
      {{"pc", uint32_t(0xAE00u)}},
      {{"pc", uint32_t(0xAE00u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedFlw_LoadsFloatFromMemory) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.flw f8, 0(x9) => f8 = mem[x9 + 0] (float)
  const auto halfword = riscv::EncodeCFlw(/*rd=*/8, /*rs1=*/9, /*uimm=*/0);

  const uint32_t float_bits = BitsFromFloat(1.5f);
  test_runner::TestOutputSpec<RISCVState> spec(
      0xAF00, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0xAF00u)},
       {"x9", uint32_t(0x6000u)}},
      {{"pc", uint32_t(0xAF02u)},
       {"f8", uint64_t(float_bits)}},
      kRV32RegAccessors);
  spec.AddPrecWrite<uint32_t>(0x6000, float_bits);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedFsw_StoresFloatToMemory) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.fsw f8, 0(x9) => mem[x9 + 0] = f8 (float)
  const auto halfword = riscv::EncodeCFsw(/*rs2=*/8, /*rs1=*/9, /*uimm=*/0);

  const uint32_t float_bits = BitsFromFloat(2.5f);
  test_runner::TestOutputSpec<RISCVState> spec(
      0xB000, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0xB000u)},
       {"x9", uint32_t(0x6000u)},
       {"f8", uint64_t(float_bits)}},
      {{"pc", uint32_t(0xB002u)}},
      kRV32RegAccessors);
  spec.AddPostRead<uint32_t>(0x6000, float_bits);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedFld_LoadsDoubleFromMemory) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.fld f8, 0(x9) => f8 = mem[x9 + 0] (double)
  const auto halfword = riscv::EncodeCFld(/*rd=*/8, /*rs1=*/9, /*uimm=*/0);

  const uint64_t double_bits = BitsFromDouble(3.14);
  test_runner::TestOutputSpec<RISCVState> spec(
      0xB100, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0xB100u)},
       {"x9", uint32_t(0x7000u)}},
      {{"pc", uint32_t(0xB102u)},
       {"f8", double_bits}},
      kRV32RegAccessors);
  spec.AddPrecWrite<uint64_t>(0x7000, double_bits);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedFsd_StoresDoubleToMemory) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.fsd f8, 0(x9) => mem[x9 + 0] = f8 (double)
  const auto halfword = riscv::EncodeCFsd(/*rs2=*/8, /*rs1=*/9, /*uimm=*/0);

  const uint64_t double_bits = BitsFromDouble(2.71);
  test_runner::TestOutputSpec<RISCVState> spec(
      0xB200, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0xB200u)},
       {"x9", uint32_t(0x7000u)},
       {"f8", double_bits}},
      {{"pc", uint32_t(0xB202u)}},
      kRV32RegAccessors);
  spec.AddPostRead<uint64_t>(0x7000, double_bits);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedFlwsp_LoadsFloatFromSp) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.flwsp f1, 4 => f1 = mem[x2 + 4] (float)
  const auto halfword = riscv::EncodeCFlwsp(/*rd=*/1, /*uimm=*/4);

  const uint32_t float_bits = BitsFromFloat(9.0f);
  test_runner::TestOutputSpec<RISCVState> spec(
      0xB300, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0xB300u)},
       {"x2", uint32_t(0x5000u)}},
      {{"pc", uint32_t(0xB302u)},
       {"f1", uint64_t(float_bits)}},
      kRV32RegAccessors);
  spec.AddPrecWrite<uint32_t>(0x5004, float_bits);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedFswsp_StoresFloatToSp) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.fswsp f1, 4 => mem[x2 + 4] = f1 (float)
  const auto halfword = riscv::EncodeCFswsp(/*rs2=*/1, /*uimm=*/4);

  const uint32_t float_bits = BitsFromFloat(9.0f);
  test_runner::TestOutputSpec<RISCVState> spec(
      0xB400, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0xB400u)},
       {"x2", uint32_t(0x5000u)},
       {"f1", uint64_t(float_bits)}},
      {{"pc", uint32_t(0xB402u)}},
      kRV32RegAccessors);
  spec.AddPostRead<uint32_t>(0x5004, float_bits);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedFldsp_LoadsDoubleFromSp) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.fldsp f1, 8 => f1 = mem[x2 + 8] (double)
  const auto halfword = riscv::EncodeCFldsp(/*rd=*/1, /*uimm=*/8);

  const uint64_t double_bits = BitsFromDouble(1.0);
  test_runner::TestOutputSpec<RISCVState> spec(
      0xB500, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0xB500u)},
       {"x2", uint32_t(0x5000u)}},
      {{"pc", uint32_t(0xB502u)},
       {"f1", double_bits}},
      kRV32RegAccessors);
  spec.AddPrecWrite<uint64_t>(0x5008, double_bits);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, CompressedFsdsp_StoresDoubleToSp) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // c.fsdsp f1, 8 => mem[x2 + 8] = f1 (double)
  const auto halfword = riscv::EncodeCFsdsp(/*rs2=*/1, /*uimm=*/8);

  const uint64_t double_bits = BitsFromDouble(1.0);
  test_runner::TestOutputSpec<RISCVState> spec(
      0xB600, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0xB600u)},
       {"x2", uint32_t(0x5000u)},
       {"f1", double_bits}},
      {{"pc", uint32_t(0xB602u)}},
      kRV32RegAccessors);
  spec.AddPostRead<uint64_t>(0x5008, double_bits);
  runner.RunTestSpec(spec);
}
