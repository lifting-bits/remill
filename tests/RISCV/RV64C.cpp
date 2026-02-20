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

TEST(RISCV64, CompressedAddi_IncrementsPcBy2) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t addr = 0xD000;

  // c.addi x1, 1
  const auto half = riscv::EncodeCAddi(/*rd=*/1, /*imm6=*/1);

  test_runner::TestOutputSpec<RISCVState> spec(
      addr, riscv::Bytes16(half),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(addr)},
       {"x1", uint64_t(41)}},
      {{"pc", uint64_t(addr + 2)},
       {"x1", uint64_t(42)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedLw_SignExtendsToXlenAndSwStoresLow32Bits) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t base = 0x5000;

  // c.lw x9, 12(x8) => sign-extends 0x80000000 to 64 bits
  const auto clw = riscv::EncodeCLw(/*rd=*/9, /*rs1=*/8, /*uimm=*/12);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x1000, riscv::Bytes16(clw),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(0x1000)},
         {"x8", uint64_t(base)}},
        {{"pc", uint64_t(0x1002)},
         {"x9", uint64_t(0xFFFF'FFFF'8000'0000ULL)}},
        kRV64RegAccessors);
    spec.AddPrecWrite<uint32_t>(base + 12, 0x8000'0000u);
    runner.RunTestSpec(spec);
  }

  // c.sw x9, 16(x8) => stores low 32 bits
  const uint32_t store_val = 0xA0B0C0D0u;
  const auto csw = riscv::EncodeCSw(/*rs2=*/9, /*rs1=*/8, /*uimm=*/16);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x1002, riscv::Bytes16(csw),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(0x1002)},
         {"x8", uint64_t(base)},
         {"x9", uint64_t(store_val)}},
        {{"pc", uint64_t(0x1004)}},
        kRV64RegAccessors);
    spec.AddPostRead<uint32_t>(base + 16, store_val);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV64, CompressedJ_JumpsRelative) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.j +8
  const auto halfword = riscv::EncodeCJ(/*imm12=*/8);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x2000, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryDirectJump,
      {{"pc", uint64_t(0x2000)}},
      {{"pc", uint64_t(0x2008)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedBeqz_TakenAndNotTaken) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.beqz x8, +8
  const auto halfword = riscv::EncodeCBeqz(/*rs1=*/8, /*imm9=*/8);

  // Taken: x8 == 0
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x3000, riscv::Bytes16(halfword),
        remill::Instruction::Category::kCategoryConditionalBranch,
        {{"pc", uint64_t(0x3000)},
         {"x8", uint64_t(0)}},
        {{"pc", uint64_t(0x3008)}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }

  // Not taken: x8 != 0
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x3000, riscv::Bytes16(halfword),
        remill::Instruction::Category::kCategoryConditionalBranch,
        {{"pc", uint64_t(0x3000)},
         {"x8", uint64_t(1)}},
        {{"pc", uint64_t(0x3002)}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV64, CompressedBnez_TakenAndNotTaken) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.bnez x8, +8
  const auto halfword = riscv::EncodeCBnez(/*rs1=*/8, /*imm9=*/8);

  // Taken: x8 != 0
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x4000, riscv::Bytes16(halfword),
        remill::Instruction::Category::kCategoryConditionalBranch,
        {{"pc", uint64_t(0x4000)},
         {"x8", uint64_t(1)}},
        {{"pc", uint64_t(0x4008)}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }

  // Not taken: x8 == 0
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x4000, riscv::Bytes16(halfword),
        remill::Instruction::Category::kCategoryConditionalBranch,
        {{"pc", uint64_t(0x4000)},
         {"x8", uint64_t(0)}},
        {{"pc", uint64_t(0x4002)}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV64, CompressedJr_JumpsToRegister) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.jr x5
  const auto halfword = riscv::EncodeCJr(/*rs1=*/5);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x5000, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryIndirectJump,
      {{"pc", uint64_t(0x5000)},
       {"x5", uint64_t(0x6000)}},
      {{"pc", uint64_t(0x6000)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedJalr_LinksAndJumpsToRegister) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.jalr x5 => x1 = pc + 2, pc = x5
  const auto halfword = riscv::EncodeCJalr(/*rs1=*/5);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x5000, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryIndirectFunctionCall,
      {{"pc", uint64_t(0x5000)},
       {"x5", uint64_t(0x7000)}},
      {{"pc", uint64_t(0x7000)},
       {"x1", uint64_t(0x5002)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedLi_LoadsImmediate) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.li x10, 15 => x10 = 15
  const auto halfword = riscv::EncodeCLi(/*rd=*/10, /*imm6=*/15);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x6000, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0x6000)}},
      {{"pc", uint64_t(0x6002)},
       {"x10", uint64_t(15)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedLi_SignExtendsNegativeImmediate) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.li x10, -1 => x10 = 0xFFFFFFFFFFFFFFFF (sign-extended to 64 bits)
  const auto halfword = riscv::EncodeCLi(/*rd=*/10, /*imm6=*/-1);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x6000, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0x6000)}},
      {{"pc", uint64_t(0x6002)},
       {"x10", uint64_t(0xFFFF'FFFF'FFFF'FFFFULL)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedMv_CopiesRegister) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.mv x10, x11 => x10 = x11
  const auto halfword = riscv::EncodeCMv(/*rd=*/10, /*rs2=*/11);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x7000, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0x7000)},
       {"x11", uint64_t(0xCAFEBABE'DEADBEEFull)}},
      {{"pc", uint64_t(0x7002)},
       {"x10", uint64_t(0xCAFEBABE'DEADBEEFull)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedAdd_AddsRegisters) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.add x10, x11 => x10 = x10 + x11
  const auto halfword = riscv::EncodeCAdd(/*rd=*/10, /*rs2=*/11);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x8000, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0x8000)},
       {"x10", uint64_t(100)},
       {"x11", uint64_t(200)}},
      {{"pc", uint64_t(0x8002)},
       {"x10", uint64_t(300)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedNop_AdvancesPcOnly) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.nop => no operation, just advance pc by 2
  const uint16_t halfword = 0x0001u;

  test_runner::TestOutputSpec<RISCVState> spec(
      0x9000, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0x9000)},
       {"x1", uint64_t(0xDEADBEEFull)}},
      {{"pc", uint64_t(0x9002)},
       {"x1", uint64_t(0xDEADBEEFull)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedAddi4spn_AddsScaledImmToSp) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.addi4spn x8, 32 => x8 = x2 + 32
  const auto halfword = riscv::EncodeCAddi4spn(/*rd=*/8, /*nzuimm=*/32);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xA000, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0xA000)},
       {"x2", uint64_t(0x1000)}},
      {{"pc", uint64_t(0xA002)},
       {"x8", uint64_t(0x1020)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedAddi16sp_AddsScaledImmToSp) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.addi16sp 32 => x2 = x2 + 32
  const auto halfword = riscv::EncodeCAddi16sp(/*nzimm=*/32);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xA200, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0xA200)},
       {"x2", uint64_t(0x1000)}},
      {{"pc", uint64_t(0xA202)},
       {"x2", uint64_t(0x1020)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedLui_LoadsUpperImmediate) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.lui x10, 1 => x10 = 1 << 12 = 0x1000
  const auto halfword = riscv::EncodeCLui(/*rd=*/10, /*nzimm=*/1);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xA300, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0xA300)}},
      {{"pc", uint64_t(0xA302)},
       {"x10", uint64_t(0x1000)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedSrli_ShiftsRightLogical) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.srli x8, 4 => x8 = x8 >> 4 (logical)
  const auto halfword = riscv::EncodeCSrli(/*rd=*/8, /*shamt=*/4);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xA400, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0xA400)},
       {"x8", uint64_t(0xF0)}},
      {{"pc", uint64_t(0xA402)},
       {"x8", uint64_t(0x0F)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedSrai_ShiftsRightArithmetic) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.srai x8, 4 => x8 = x8 >> 4 (arithmetic)
  const auto halfword = riscv::EncodeCSrai(/*rd=*/8, /*shamt=*/4);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xA500, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0xA500)},
       {"x8", uint64_t(0xFFFFFFFF'FFFFFF00ull)}},
      {{"pc", uint64_t(0xA502)},
       {"x8", uint64_t(0xFFFFFFFF'FFFFFFF0ull)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedAndi_AndsImmediate) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.andi x8, 0xF => x8 = x8 & 0xF
  const auto halfword = riscv::EncodeCAndi(/*rd=*/8, /*imm6=*/0xF);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xA600, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0xA600)},
       {"x8", uint64_t(0xFF)}},
      {{"pc", uint64_t(0xA602)},
       {"x8", uint64_t(0x0F)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedSub_SubtractsRegisters) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.sub x8, x9 => x8 = x8 - x9
  const auto halfword = riscv::EncodeCSub(/*rd=*/8, /*rs2=*/9);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xA700, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0xA700)},
       {"x8", uint64_t(10)},
       {"x9", uint64_t(3)}},
      {{"pc", uint64_t(0xA702)},
       {"x8", uint64_t(7)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedXor_XorsRegisters) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.xor x8, x9 => x8 = x8 ^ x9
  const auto halfword = riscv::EncodeCXor(/*rd=*/8, /*rs2=*/9);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xA800, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0xA800)},
       {"x8", uint64_t(0xFF)},
       {"x9", uint64_t(0x0F)}},
      {{"pc", uint64_t(0xA802)},
       {"x8", uint64_t(0xF0)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedOr_OrsRegisters) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.or x8, x9 => x8 = x8 | x9
  const auto halfword = riscv::EncodeCOr(/*rd=*/8, /*rs2=*/9);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xA900, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0xA900)},
       {"x8", uint64_t(0xF0)},
       {"x9", uint64_t(0x0F)}},
      {{"pc", uint64_t(0xA902)},
       {"x8", uint64_t(0xFF)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedAnd_AndsRegisters) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.and x8, x9 => x8 = x8 & x9
  const auto halfword = riscv::EncodeCAnd(/*rd=*/8, /*rs2=*/9);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xAA00, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0xAA00)},
       {"x8", uint64_t(0xFF)},
       {"x9", uint64_t(0x0F)}},
      {{"pc", uint64_t(0xAA02)},
       {"x8", uint64_t(0x0F)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedSlli_ShiftsLeftLogical) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.slli x10, 4 => x10 = x10 << 4
  const auto halfword = riscv::EncodeCSlli(/*rd=*/10, /*shamt=*/4);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xAB00, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0xAB00)},
       {"x10", uint64_t(0x0F)}},
      {{"pc", uint64_t(0xAB02)},
       {"x10", uint64_t(0xF0)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedLwsp_LoadsWordFromSp) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.lwsp x10, 8 => x10 = sign-extend(mem[x2 + 8])
  const auto halfword = riscv::EncodeCLwsp(/*rd=*/10, /*uimm=*/8);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xAC00, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0xAC00)},
       {"x2", uint64_t(0x5000)}},
      {{"pc", uint64_t(0xAC02)},
       {"x10", uint64_t(0xFFFF'FFFF'DEAD'BEEFull)}},
      kRV64RegAccessors);
  spec.AddPrecWrite<uint32_t>(0x5008, 0xDEADBEEFu);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedSwsp_StoresWordToSp) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.swsp x10, 12 => mem[x2 + 12] = x10 (low 32 bits)
  const auto halfword = riscv::EncodeCSwsp(/*rs2=*/10, /*uimm=*/12);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xAD00, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0xAD00)},
       {"x2", uint64_t(0x5000)},
       {"x10", uint64_t(0xCAFEBABEu)}},
      {{"pc", uint64_t(0xAD02)}},
      kRV64RegAccessors);
  spec.AddPostRead<uint32_t>(0x500C, 0xCAFEBABEu);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedEbreak_TriggersError) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.ebreak => raw encoding 0x9002
  const uint16_t halfword = 0x9002u;

  test_runner::TestOutputSpec<RISCVState> spec(
      0xAE00, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryError,
      {{"pc", uint64_t(0xAE00)}},
      {{"pc", uint64_t(0xAE02)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedAddiw_AddsImmWord) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.addiw x10, 5 => x10 = sign-extend32(x10[31:0] + 5)
  const auto halfword = riscv::EncodeCAddiw(/*rd=*/10, /*imm6=*/5);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xB000, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0xB000)},
       {"x10", uint64_t(0xFFFF'FFFF'FFFF'FFFEull)}},
      {{"pc", uint64_t(0xB002)},
       {"x10", uint64_t(3)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedSubw_SubtractsWordRegisters) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.subw x8, x9 => x8 = sign-extend32(x8[31:0] - x9[31:0])
  const auto halfword = riscv::EncodeCSubw(/*rd=*/8, /*rs2=*/9);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xB100, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0xB100)},
       {"x8", uint64_t(10)},
       {"x9", uint64_t(3)}},
      {{"pc", uint64_t(0xB102)},
       {"x8", uint64_t(7)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedAddw_AddsWordRegisters) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.addw x8, x9 => x8 = sign-extend32(x8[31:0] + x9[31:0])
  const auto halfword = riscv::EncodeCAddw(/*rd=*/8, /*rs2=*/9);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xB200, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0xB200)},
       {"x8", uint64_t(0xFFFFFFFF)},
       {"x9", uint64_t(1)}},
      {{"pc", uint64_t(0xB202)},
       {"x8", uint64_t(0)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedLd_LoadsDoubleword) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.ld x9, 0(x8) => x9 = mem[x8 + 0] (64-bit)
  const auto halfword = riscv::EncodeCLd(/*rd=*/9, /*rs1=*/8, /*uimm=*/0);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xB300, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0xB300)},
       {"x8", uint64_t(0x7000)}},
      {{"pc", uint64_t(0xB302)},
       {"x9", uint64_t(0xDEADBEEF'CAFEBABEull)}},
      kRV64RegAccessors);
  spec.AddPrecWrite<uint64_t>(0x7000, 0xDEADBEEF'CAFEBABEull);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedSd_StoresDoubleword) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.sd x9, 8(x8) => mem[x8 + 8] = x9 (64-bit)
  const auto halfword = riscv::EncodeCSd(/*rs2=*/9, /*rs1=*/8, /*uimm=*/8);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xB400, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0xB400)},
       {"x8", uint64_t(0x7000)},
       {"x9", uint64_t(0x1234'5678'9ABC'DEF0ull)}},
      {{"pc", uint64_t(0xB402)}},
      kRV64RegAccessors);
  spec.AddPostRead<uint64_t>(0x7008, 0x1234'5678'9ABC'DEF0ull);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedLdsp_LoadsDoublewordFromSp) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.ldsp x10, 8 => x10 = mem[x2 + 8] (64-bit)
  const auto halfword = riscv::EncodeCLdsp(/*rd=*/10, /*uimm=*/8);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xB500, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0xB500)},
       {"x2", uint64_t(0x5000)}},
      {{"pc", uint64_t(0xB502)},
       {"x10", uint64_t(0xAAAA'BBBB'CCCC'DDDDull)}},
      kRV64RegAccessors);
  spec.AddPrecWrite<uint64_t>(0x5008, 0xAAAA'BBBB'CCCC'DDDDull);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedSdsp_StoresDoublewordToSp) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.sdsp x10, 16 => mem[x2 + 16] = x10 (64-bit)
  const auto halfword = riscv::EncodeCSdsp(/*rs2=*/10, /*uimm=*/16);

  test_runner::TestOutputSpec<RISCVState> spec(
      0xB600, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0xB600)},
       {"x2", uint64_t(0x5000)},
       {"x10", uint64_t(0x1111'2222'3333'4444ull)}},
      {{"pc", uint64_t(0xB602)}},
      kRV64RegAccessors);
  spec.AddPostRead<uint64_t>(0x5010, 0x1111'2222'3333'4444ull);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedFld_LoadsDoubleFromMemory) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.fld f8, 0(x9) => f8 = mem[x9 + 0] (double)
  const auto halfword = riscv::EncodeCFld(/*rd=*/8, /*rs1=*/9, /*uimm=*/0);

  const uint64_t double_bits = BitsFromDouble(3.14);
  test_runner::TestOutputSpec<RISCVState> spec(
      0xB700, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0xB700)},
       {"x9", uint64_t(0x7000)}},
      {{"pc", uint64_t(0xB702)},
       {"f8", double_bits}},
      kRV64RegAccessors);
  spec.AddPrecWrite<uint64_t>(0x7000, double_bits);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedFsd_StoresDoubleToMemory) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.fsd f8, 0(x9) => mem[x9 + 0] = f8 (double)
  const auto halfword = riscv::EncodeCFsd(/*rs2=*/8, /*rs1=*/9, /*uimm=*/0);

  const uint64_t double_bits = BitsFromDouble(2.71);
  test_runner::TestOutputSpec<RISCVState> spec(
      0xB800, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0xB800)},
       {"x9", uint64_t(0x7000)},
       {"f8", double_bits}},
      {{"pc", uint64_t(0xB802)}},
      kRV64RegAccessors);
  spec.AddPostRead<uint64_t>(0x7000, double_bits);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedFldsp_LoadsDoubleFromSp) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.fldsp f1, 8 => f1 = mem[x2 + 8] (double)
  const auto halfword = riscv::EncodeCFldsp(/*rd=*/1, /*uimm=*/8);

  const uint64_t double_bits = BitsFromDouble(1.0);
  test_runner::TestOutputSpec<RISCVState> spec(
      0xB900, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0xB900)},
       {"x2", uint64_t(0x5000)}},
      {{"pc", uint64_t(0xB902)},
       {"f1", double_bits}},
      kRV64RegAccessors);
  spec.AddPrecWrite<uint64_t>(0x5008, double_bits);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedFsdsp_StoresDoubleToSp) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.fsdsp f1, 8 => mem[x2 + 8] = f1 (double)
  const auto halfword = riscv::EncodeCFsdsp(/*rs2=*/1, /*uimm=*/8);

  const uint64_t double_bits = BitsFromDouble(1.0);
  test_runner::TestOutputSpec<RISCVState> spec(
      0xBA00, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0xBA00)},
       {"x2", uint64_t(0x5000)},
       {"f1", double_bits}},
      {{"pc", uint64_t(0xBA02)}},
      kRV64RegAccessors);
  spec.AddPostRead<uint64_t>(0x5008, double_bits);
  runner.RunTestSpec(spec);
}
