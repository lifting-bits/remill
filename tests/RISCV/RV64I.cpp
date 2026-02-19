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
#include <vector>

#include "RISCVTestSpec.h"
#include "TestUtil.h"

// -- RV64I ALU ----------------------------------------------------------------

TEST(RISCV64, X0WriteIsIgnored_Addi) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // addi x0, x0, 1  => 0x00100013
  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(0x00100013U),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0x1000)},
       {"x0", uint64_t(0x0123456789ABCDEFu)}},
      {{"x0", uint64_t(0)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, X0ReadAsZero_Addi) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // addi x1, x0, 5  => 0x00500093
  test_runner::TestOutputSpec<RISCVState> spec(
      0x2000, riscv::Bytes32(0x00500093U),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0x2000)},
       {"x0", uint64_t(0xDEADBEEFu)},
       {"x1", uint64_t(0)}},
      {{"x0", uint64_t(0)},
       {"x1", uint64_t(5)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, PcIs64Bit_AddiAtHighAddress) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t addr = 0x1234'5678'9000ULL;

  // addi x1, x0, 1
  const auto word = riscv::EncodeI(riscv::kOpcodeOpImm, /*rd=*/1, /*funct3=*/0,
                                   /*rs1=*/0, /*imm12=*/1);

  test_runner::TestOutputSpec<RISCVState> spec(
      addr, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(addr)},
       {"x1", uint64_t(0)}},
      {{"pc", uint64_t(addr + 4)},
       {"x1", uint64_t(1)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, Addi_NegativeImmediate) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t addr = 0x3000;

  // addi x1, x0, -1
  const auto word = riscv::EncodeI(riscv::kOpcodeOpImm, /*rd=*/1, /*funct3=*/0,
                                   /*rs1=*/0, /*imm12=*/-1);

  test_runner::TestOutputSpec<RISCVState> spec(
      addr, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(addr)},
       {"x1", uint64_t(0)}},
      {{"pc", uint64_t(addr + 4)},
       {"x1", uint64_t(0xFFFF'FFFF'FFFF'FFFFULL)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, Add_Sub) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t addr = 0x4000;

  // add x3, x1, x2
  const auto add_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/3, /*funct3=*/0, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x00);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr, riscv::Bytes32(add_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(addr)},
         {"x1", uint64_t(1)},
         {"x2", uint64_t(2)}},
        {{"pc", uint64_t(addr + 4)},
         {"x3", uint64_t(3)}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }

  // sub x4, x2, x1
  const auto sub_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/4, /*funct3=*/0, /*rs1=*/2,
                     /*rs2=*/1, /*funct7=*/0x20);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr + 4, riscv::Bytes32(sub_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(addr + 4)},
         {"x1", uint64_t(1)},
         {"x2", uint64_t(2)}},
        {{"pc", uint64_t(addr + 8)},
         {"x4", uint64_t(1)}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV64, Slt_Sltu_SignedVsUnsigned) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t addr = 0x6000;

  // slt x3, x1, x2  (signed: -1 < 1 => 1)
  const auto slt_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/3, /*funct3=*/0x2, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x00);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr, riscv::Bytes32(slt_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(addr)},
         {"x1", uint64_t(0xFFFF'FFFF'FFFF'FFFFULL)},
         {"x2", uint64_t(1)}},
        {{"x3", uint64_t(1)}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }

  // sltu x4, x1, x2 (unsigned: MAX > 1 => 0)
  const auto sltu_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/4, /*funct3=*/0x3, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x00);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr + 4, riscv::Bytes32(sltu_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(addr + 4)},
         {"x1", uint64_t(0xFFFF'FFFF'FFFF'FFFFULL)},
         {"x2", uint64_t(1)}},
        {{"x4", uint64_t(0)}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV64, ShiftImmediate_SrliVsSrai) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t addr = 0x7000;

  // srli x2, x1, 1
  const auto srli_word = riscv::EncodeShiftI64(/*funct3=*/0x5, /*rd=*/2,
                                               /*rs1=*/1, /*shamt=*/1,
                                               /*funct6=*/0x00);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr, riscv::Bytes32(srli_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(addr)},
         {"x1", uint64_t(0x8000'0000'0000'0000ULL)}},
        {{"x2", uint64_t(0x4000'0000'0000'0000ULL)}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }

  // srai x3, x1, 1
  const auto srai_word = riscv::EncodeShiftI64(/*funct3=*/0x5, /*rd=*/3,
                                               /*rs1=*/1, /*shamt=*/1,
                                               /*funct6=*/0x10);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr + 4, riscv::Bytes32(srai_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(addr + 4)},
         {"x1", uint64_t(0x8000'0000'0000'0000ULL)}},
        {{"x3", uint64_t(0xC000'0000'0000'0000ULL)}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }
}

// -- RV64I U-type -------------------------------------------------------------

TEST(RISCV64, Lui_SignExtendsUpperImmediateToXlen) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t addr = 0x1000;

  // lui x1, 0x80000 => x1 = 0xFFFF_FFFF_8000_0000
  const auto word =
      riscv::EncodeU(riscv::kOpcodeLui, /*rd=*/1, /*imm20=*/0x80000);

  test_runner::TestOutputSpec<RISCVState> spec(
      addr, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(addr)}, {"x1", uint64_t(0u)}},
      {{"pc", uint64_t(addr + 4)},
       {"x1", uint64_t(0xFFFF'FFFF'8000'0000ULL)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, Auipc_AddsPcRelativeUpperImmediate) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t addr = 0x2000;

  // auipc x1, 0x1 => x1 = pc + 0x1000
  const auto word =
      riscv::EncodeU(riscv::kOpcodeAuipc, /*rd=*/1, /*imm20=*/0x1);

  test_runner::TestOutputSpec<RISCVState> spec(
      addr, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(addr)}, {"x1", uint64_t(0u)}},
      {{"pc", uint64_t(addr + 4)}, {"x1", uint64_t(addr + 0x1000)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

// -- RV64I memory -------------------------------------------------------------

TEST(RISCV64, LoadSignExtension_LwAndLwu) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t addr = 0x8000;
  const uint64_t mem_addr = 0x10000;

  // lw x2, 0(x1)  => sign-extends
  const auto lw_word =
      riscv::EncodeI(riscv::kOpcodeLoad, /*rd=*/2, /*funct3=*/0x2,
                     /*rs1=*/1, /*imm12=*/0);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr, riscv::Bytes32(lw_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(addr)},
         {"x1", uint64_t(mem_addr)}},
        {{"x2", uint64_t(0xFFFF'FFFF'8000'0000ULL)}},
        kRV64RegAccessors);
    spec.AddPrecWrite<uint32_t>(mem_addr, 0x8000'0000u);
    runner.RunTestSpec(spec);
  }

  // lwu x3, 0(x1) => zero-extends
  const auto lwu_word =
      riscv::EncodeI(riscv::kOpcodeLoad, /*rd=*/3, /*funct3=*/0x6, /*rs1=*/1,
                     /*imm12=*/0);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr + 4, riscv::Bytes32(lwu_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(addr + 4)},
         {"x1", uint64_t(mem_addr)}},
        {{"x3", uint64_t(0x0000'0000'8000'0000ULL)}},
        kRV64RegAccessors);
    spec.AddPrecWrite<uint32_t>(mem_addr, 0x8000'0000u);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV64, StoreDoubleword_Sd) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t addr = 0x9000;
  const uint64_t mem_addr = 0x20000;

  // sd x2, 0(x1)
  const auto sd_word =
      riscv::EncodeS(riscv::kOpcodeStore, /*funct3=*/0x3, /*rs1=*/1, /*rs2=*/2,
                     /*imm12=*/0);

  test_runner::TestOutputSpec<RISCVState> spec(
      addr, riscv::Bytes32(sd_word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(addr)},
       {"x1", uint64_t(mem_addr)},
       {"x2", uint64_t(0x1122'3344'5566'7788ULL)}},
      {{"pc", uint64_t(addr + 4)}},
      kRV64RegAccessors);
  spec.AddPostRead<uint64_t>(mem_addr, 0x1122'3344'5566'7788ULL);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, LoadDoubleword_Ld) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t addr = 0x1000;
  const uint64_t mem_addr = 0x10000;

  // ld x2, 0(x1)
  const auto ld_word =
      riscv::EncodeI(riscv::kOpcodeLoad, /*rd=*/2, /*funct3=*/0x3, /*rs1=*/1,
                     /*imm12=*/0);

  test_runner::TestOutputSpec<RISCVState> spec(
      addr, riscv::Bytes32(ld_word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(addr)}, {"x1", uint64_t(mem_addr)}},
      {{"pc", uint64_t(addr + 4)},
       {"x2", uint64_t(0x1122'3344'5566'7788ULL)}},
      kRV64RegAccessors);
  spec.AddPrecWrite<uint64_t>(mem_addr, 0x1122'3344'5566'7788ULL);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, LoadHalfwordSignAndZeroExtension_Lh_Lhu) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t addr = 0x2000;
  const uint64_t mem_addr = 0x20000;

  // lh x2, 0(x1)
  const auto lh_word =
      riscv::EncodeI(riscv::kOpcodeLoad, /*rd=*/2, /*funct3=*/0x1, /*rs1=*/1,
                     /*imm12=*/0);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr, riscv::Bytes32(lh_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(addr)}, {"x1", uint64_t(mem_addr)}},
        {{"pc", uint64_t(addr + 4)},
         {"x2", uint64_t(0xFFFF'FFFF'FFFF'8001ULL)}},
        kRV64RegAccessors);
    spec.AddPrecWrite<uint16_t>(mem_addr, 0x8001u);
    runner.RunTestSpec(spec);
  }

  // lhu x3, 0(x1)
  const auto lhu_word =
      riscv::EncodeI(riscv::kOpcodeLoad, /*rd=*/3, /*funct3=*/0x5, /*rs1=*/1,
                     /*imm12=*/0);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr + 4, riscv::Bytes32(lhu_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(addr + 4)}, {"x1", uint64_t(mem_addr)}},
        {{"pc", uint64_t(addr + 8)},
         {"x3", uint64_t(0x0000'0000'0000'8001ULL)}},
        kRV64RegAccessors);
    spec.AddPrecWrite<uint16_t>(mem_addr, 0x8001u);
    runner.RunTestSpec(spec);
  }
}

// -- RV64I control flow -------------------------------------------------------

TEST(RISCV64, Jal_SetsLinkRegisterAndPc) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t addr = 0xB000;

  // jal x5, +8
  const auto jal_word =
      riscv::EncodeJ(riscv::kOpcodeJal, /*rd=*/5, /*imm21=*/8);

  test_runner::TestOutputSpec<RISCVState> spec(
      addr, riscv::Bytes32(jal_word),
      remill::Instruction::Category::kCategoryDirectFunctionCall,
      {{"pc", uint64_t(addr)},
       {"x5", uint64_t(0)}},
      {{"pc", uint64_t(addr + 8)},
       {"x5", uint64_t(addr + 4)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, Jalr_ClearsTargetLsbAndSetsLink) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t addr = 0x1000;

  // jalr x5, 0(x2)
  const auto word =
      riscv::EncodeI(riscv::kOpcodeJalr, /*rd=*/5, /*funct3=*/0, /*rs1=*/2,
                     /*imm12=*/0);

  test_runner::TestOutputSpec<RISCVState> spec(
      addr, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryIndirectFunctionCall,
      {{"pc", uint64_t(addr)},
       {"x2", uint64_t(0x0000'0000'0000'2001ULL)},
       {"x5", uint64_t(0u)}},
      {{"pc", uint64_t(0x2000u)}, {"x5", uint64_t(addr + 4)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, Branches_AllConditions_TakenAndNotTaken) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  struct Case {
    uint32_t funct3;
    uint64_t rs1;
    uint64_t rs2;
    bool taken;
  };

  const std::vector<Case> cases = {
      {0x0, 0x11u, 0x11u, true},
      {0x0, 0x11u, 0x22u, false},
      {0x1, 0x11u, 0x22u, true},
      {0x1, 0x11u, 0x11u, false},
      {0x4, 0xFFFF'FFFF'FFFF'FFFFULL, 1u, true},
      {0x4, 2u, 1u, false},
      {0x5, 2u, 1u, true},
      {0x5, 0xFFFF'FFFF'FFFF'FFFFULL, 1u, false},
      {0x6, 1u, 0xFFFF'FFFF'FFFF'FFFFULL, true},
      {0x6, 0xFFFF'FFFF'FFFF'FFFFULL, 1u, false},
      {0x7, 0xFFFF'FFFF'FFFF'FFFFULL, 1u, true},
      {0x7, 1u, 0xFFFF'FFFF'FFFF'FFFFULL, false},
  };

  for (const auto &tc : cases) {
    const uint64_t addr = 0x3000;
    const uint64_t target = addr + 8;

    const auto word =
        riscv::EncodeB(riscv::kOpcodeBranch, tc.funct3, /*rs1=*/1,
                       /*rs2=*/2, /*imm13=*/8);

    const uint64_t expected_pc = tc.taken ? target : (addr + 4);

    test_runner::TestOutputSpec<RISCVState> spec(
        addr, riscv::Bytes32(word),
        remill::Instruction::Category::kCategoryConditionalBranch,
        {{"pc", uint64_t(addr)},
         {"x1", uint64_t(tc.rs1)},
         {"x2", uint64_t(tc.rs2)}},
        {{"pc", uint64_t(expected_pc)}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }
}

// -- RV64I W-ops (32-bit on 64-bit) ------------------------------------------

TEST(RISCV64, Addiw_SignExtends32BitResult) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t addr = 0x1000;

  // addiw x2, x0, -1
  const auto word =
      riscv::EncodeI(riscv::kOpcodeOpImm32, /*rd=*/2, /*funct3=*/0, /*rs1=*/0,
                     /*imm12=*/-1);

  test_runner::TestOutputSpec<RISCVState> spec(
      addr, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(addr)}, {"x2", uint64_t(0u)}},
      {{"pc", uint64_t(addr + 4)},
       {"x2", uint64_t(0xFFFF'FFFF'FFFF'FFFFULL)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, Addw_UsesLow32BitsAndSignExtends) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t addr = 0x2000;

  // addw x3, x1, x2
  const auto word =
      riscv::EncodeR(riscv::kOpcodeOp32, /*rd=*/3, /*funct3=*/0, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x00);

  test_runner::TestOutputSpec<RISCVState> spec(
      addr, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(addr)},
       {"x1", uint64_t(0x0000'0000'8000'0000ULL)},
       {"x2", uint64_t(0u)},
       {"x3", uint64_t(0u)}},
      {{"pc", uint64_t(addr + 4)},
       {"x3", uint64_t(0xFFFF'FFFF'8000'0000ULL)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

// -- RV64I system (ecall/ebreak) ----------------------------------------------

TEST(RISCV64, EcallAndEbreak_SetHyperCallMarker) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);
  auto &lifter = runner.GetLifter();

  test_runner::MemoryHandler mem(llvm::endianness::little);
  RISCVState st = {};

  // ecall => 0x00000073
  const uint64_t ecall_addr = 0xC000;
  st = {};
  st.hyper_call = AsyncHyperCall::kInvalid;
  st.pc.qword = ecall_addr;
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_ecall", riscv::Bytes32(0x0000'0073U), ecall_addr, &st,
      &mem);
  EXPECT_EQ(st.hyper_call, AsyncHyperCall::kRISCVSysCall);

  // ebreak => 0x00100073
  const uint64_t ebreak_addr = 0xC100;
  st = {};
  st.hyper_call = AsyncHyperCall::kInvalid;
  st.pc.qword = ebreak_addr;
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_ebreak", riscv::Bytes32(0x0010'0073U), ebreak_addr, &st,
      &mem);
  EXPECT_EQ(st.hyper_call, AsyncHyperCall::kRISCVBreak);
}
