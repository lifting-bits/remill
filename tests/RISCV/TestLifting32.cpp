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

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <llvm/IR/LLVMContext.h>
#include <remill/Arch/Instruction.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>

#include <cstdint>
#include <vector>

#include "RISCVTestSpec.h"
#include "TestUtil.h"

// -- RV32I ALU ----------------------------------------------------------------

TEST(RISCV32, X0WriteIsIgnored_Addi) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // addi x0, x0, 1  => 0x00100013
  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(0x00100013U),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"x0", uint32_t(0x12345678u)}},
      {{"x0", uint32_t(0u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, X0ReadAsZero_Addi) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // addi x1, x0, 5  => 0x00500093
  test_runner::TestOutputSpec<RISCVState> spec(
      0x2000, riscv::Bytes32(0x00500093U),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x2000u)},
       {"x0", uint32_t(0xDEADBEEFu)},
       {"x1", uint32_t(0u)}},
      {{"x0", uint32_t(0u)},
       {"x1", uint32_t(5u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, Addi_NegativeImmediate) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // addi x1, x0, -1
  const auto word = riscv::EncodeI(riscv::kOpcodeOpImm, /*rd=*/1, /*funct3=*/0,
                                   /*rs1=*/0, /*imm12=*/-1);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x3000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x3000u)},
       {"x1", uint32_t(0u)}},
      {{"x1", uint32_t(0xFFFF'FFFFu)},
       {"pc", uint32_t(0x3004u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, Add_Sub) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // add x3, x1, x2
  const auto add_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/3, /*funct3=*/0, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x00);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x4000, riscv::Bytes32(add_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(0x4000u)},
         {"x1", uint32_t(1u)},
         {"x2", uint32_t(2u)},
         {"x3", uint32_t(0u)}},
        {{"x3", uint32_t(3u)},
         {"pc", uint32_t(0x4004u)}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }

  // sub x4, x2, x1
  const auto sub_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/4, /*funct3=*/0, /*rs1=*/2,
                     /*rs2=*/1, /*funct7=*/0x20);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x4004, riscv::Bytes32(sub_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(0x4004u)},
         {"x1", uint32_t(1u)},
         {"x2", uint32_t(2u)},
         {"x4", uint32_t(0u)}},
        {{"x4", uint32_t(1u)},
         {"pc", uint32_t(0x4008u)}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV32, And_Or_Xor_Immediate) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // andi x2, x1, 0x0F0
  const auto andi_word =
      riscv::EncodeI(riscv::kOpcodeOpImm, /*rd=*/2, /*funct3=*/0x7, /*rs1=*/1,
                     /*imm12=*/0x0F0);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x5000, riscv::Bytes32(andi_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(0x5000u)},
         {"x1", uint32_t(0xF0F0'00FFu)}},
        {{"x2", uint32_t(0x0000'00F0u)},
         {"pc", uint32_t(0x5004u)}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }

  // ori x3, x1, 0x00F
  const auto ori_word =
      riscv::EncodeI(riscv::kOpcodeOpImm, /*rd=*/3, /*funct3=*/0x6, /*rs1=*/1,
                     /*imm12=*/0x00F);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x5004, riscv::Bytes32(ori_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(0x5004u)},
         {"x1", uint32_t(0xF0F0'00FFu)}},
        {{"x3", uint32_t(0xF0F0'00FFu)},
         {"pc", uint32_t(0x5008u)}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }

  // xori x4, x1, 0x0FF
  const auto xori_word =
      riscv::EncodeI(riscv::kOpcodeOpImm, /*rd=*/4, /*funct3=*/0x4, /*rs1=*/1,
                     /*imm12=*/0x0FF);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x5008, riscv::Bytes32(xori_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(0x5008u)},
         {"x1", uint32_t(0xF0F0'00FFu)}},
        {{"x4", uint32_t(0xF0F0'0000u)},
         {"pc", uint32_t(0x500Cu)}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV32, Slt_Sltu_SignedVsUnsigned) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // slt x3, x1, x2  (signed: -1 < 1 => 1)
  const auto slt_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/3, /*funct3=*/0x2, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x00);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x6000, riscv::Bytes32(slt_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(0x6000u)},
         {"x1", uint32_t(0xFFFF'FFFFu)},
         {"x2", uint32_t(1u)}},
        {{"x3", uint32_t(1u)},
         {"pc", uint32_t(0x6004u)}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }

  // sltu x4, x1, x2 (unsigned: 0xFFFFFFFF > 1 => 0)
  const auto sltu_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/4, /*funct3=*/0x3, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x00);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x6004, riscv::Bytes32(sltu_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(0x6004u)},
         {"x1", uint32_t(0xFFFF'FFFFu)},
         {"x2", uint32_t(1u)}},
        {{"x4", uint32_t(0u)},
         {"pc", uint32_t(0x6008u)}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }
}

// -- RV32I shifts -------------------------------------------------------------

TEST(RISCV32, ShiftImmediate_SrliVsSrai) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // srli x2, x1, 1
  const auto srli_word = riscv::EncodeShiftI32(/*funct3=*/0x5, /*rd=*/2,
                                               /*rs1=*/1, /*shamt=*/1,
                                               /*funct7=*/0x00);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x7000, riscv::Bytes32(srli_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(0x7000u)},
         {"x1", uint32_t(0x8000'0000u)}},
        {{"x2", uint32_t(0x4000'0000u)},
         {"pc", uint32_t(0x7004u)}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }

  // srai x3, x1, 1
  const auto srai_word = riscv::EncodeShiftI32(/*funct3=*/0x5, /*rd=*/3,
                                               /*rs1=*/1, /*shamt=*/1,
                                               /*funct7=*/0x20);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x7004, riscv::Bytes32(srai_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(0x7004u)},
         {"x1", uint32_t(0x8000'0000u)}},
        {{"x3", uint32_t(0xC000'0000u)},
         {"pc", uint32_t(0x7008u)}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV32, Slli_AndRegisterShiftMasking) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t addr = 0x1000;

  // slli x2, x1, 31
  const auto slli_word = riscv::EncodeShiftI32(/*funct3=*/0x1, /*rd=*/2,
                                               /*rs1=*/1, /*shamt=*/31,
                                               /*funct7=*/0x00);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr, riscv::Bytes32(slli_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(addr)}, {"x1", uint32_t(1u)}},
        {{"x2", uint32_t(0x8000'0000u)},
         {"pc", uint32_t(addr + 4)}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }

  // sll x3, x1, x2  with x2=37 should shift by (37 & 31) == 5
  const auto sll_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/3, /*funct3=*/0x1, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x00);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr + 4, riscv::Bytes32(sll_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(addr + 4)},
         {"x1", uint32_t(1u)},
         {"x2", uint32_t(37u)}},
        {{"x3", uint32_t(0x20u)},
         {"pc", uint32_t(addr + 8)}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV32, SrlVsSra_RegisterShift) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t addr = 0x2000;

  // srl x3, x1, x2
  const auto srl_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/3, /*funct3=*/0x5, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x00);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr, riscv::Bytes32(srl_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(addr)},
         {"x1", uint32_t(0x8000'0000u)},
         {"x2", uint32_t(1u)}},
        {{"x3", uint32_t(0x4000'0000u)},
         {"pc", uint32_t(addr + 4)}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }

  // sra x4, x1, x2
  const auto sra_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/4, /*funct3=*/0x5, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x20);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr + 4, riscv::Bytes32(sra_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(addr + 4)},
         {"x1", uint32_t(0x8000'0000u)},
         {"x2", uint32_t(1u)}},
        {{"x4", uint32_t(0xC000'0000u)},
         {"pc", uint32_t(addr + 8)}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }
}

// -- RV32I U-type -------------------------------------------------------------

TEST(RISCV32, Lui_SetsUpperImmediate) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t addr = 0x1000;

  // lui x1, 0x12345  => x1 = 0x12345000
  const auto word =
      riscv::EncodeU(riscv::kOpcodeLui, /*rd=*/1, /*imm20=*/0x12345);

  test_runner::TestOutputSpec<RISCVState> spec(
      addr, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(addr)}, {"x1", uint32_t(0u)}},
      {{"x1", uint32_t(0x12345'000u)},
       {"pc", uint32_t(addr + 4)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, Auipc_AddsPcRelativeUpperImmediate) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t addr = 0x2000;

  // auipc x1, 0x1 => x1 = pc + 0x1000
  const auto word =
      riscv::EncodeU(riscv::kOpcodeAuipc, /*rd=*/1, /*imm20=*/0x1);

  test_runner::TestOutputSpec<RISCVState> spec(
      addr, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(addr)}, {"x1", uint32_t(0u)}},
      {{"x1", uint32_t(addr + 0x1000)},
       {"pc", uint32_t(addr + 4)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

// -- RV32I memory -------------------------------------------------------------

TEST(RISCV32, LoadSignAndZeroExtension_Lb_Lbu) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t mem_addr = 0x10000;

  // lb x2, 0(x1)
  const auto lb_word = riscv::EncodeI(riscv::kOpcodeLoad, /*rd=*/2,
                                      /*funct3=*/0, /*rs1=*/1, /*imm12=*/0);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x8000, riscv::Bytes32(lb_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(0x8000u)},
         {"x1", uint32_t(static_cast<uint32_t>(mem_addr))}},
        {{"x2", uint32_t(0xFFFF'FF80u)},
         {"pc", uint32_t(0x8004u)}},
        kRV32RegAccessors);
    spec.AddPrecWrite<uint8_t>(mem_addr, uint8_t(0x80u));
    runner.RunTestSpec(spec);
  }

  // lbu x3, 0(x1)
  const auto lbu_word =
      riscv::EncodeI(riscv::kOpcodeLoad, /*rd=*/3, /*funct3=*/0x4, /*rs1=*/1,
                     /*imm12=*/0);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x8004, riscv::Bytes32(lbu_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(0x8004u)},
         {"x1", uint32_t(static_cast<uint32_t>(mem_addr))}},
        {{"x3", uint32_t(0x0000'0080u)},
         {"pc", uint32_t(0x8008u)}},
        kRV32RegAccessors);
    spec.AddPrecWrite<uint8_t>(mem_addr, uint8_t(0x80u));
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV32, StoreByteAndHalfword_Sb_Sh) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t mem_addr = 0x20000;

  // sb x2, 0(x1)
  const auto sb_word =
      riscv::EncodeS(riscv::kOpcodeStore, /*funct3=*/0, /*rs1=*/1, /*rs2=*/2,
                     /*imm12=*/0);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x9000, riscv::Bytes32(sb_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(0x9000u)},
         {"x1", uint32_t(static_cast<uint32_t>(mem_addr))},
         {"x2", uint32_t(0xA1B2'C3D4u)}},
        {{"pc", uint32_t(0x9004u)}},
        kRV32RegAccessors);
    spec.AddPostRead<uint8_t>(mem_addr, uint8_t(0xD4u));
    runner.RunTestSpec(spec);
  }

  // sh x2, 2(x1)
  const auto sh_word =
      riscv::EncodeS(riscv::kOpcodeStore, /*funct3=*/0x1, /*rs1=*/1, /*rs2=*/2,
                     /*imm12=*/2);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x9004, riscv::Bytes32(sh_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(0x9004u)},
         {"x1", uint32_t(static_cast<uint32_t>(mem_addr))},
         {"x2", uint32_t(0xA1B2'C3D4u)}},
        {{"pc", uint32_t(0x9008u)}},
        kRV32RegAccessors);
    spec.AddPostRead<uint16_t>(mem_addr + 2, uint16_t(0xC3D4u));
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV32, LoadHalfwordSignAndZeroExtension_Lh_Lhu) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t addr = 0x1000;
  const uint64_t mem_addr = 0x10000;

  // lh x2, 0(x1)
  const auto lh_word =
      riscv::EncodeI(riscv::kOpcodeLoad, /*rd=*/2, /*funct3=*/0x1, /*rs1=*/1,
                     /*imm12=*/0);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr, riscv::Bytes32(lh_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(addr)},
         {"x1", uint32_t(mem_addr)}},
        {{"x2", uint32_t(0xFFFF'8001u)},
         {"pc", uint32_t(addr + 4)}},
        kRV32RegAccessors);
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
        {{"pc", uint32_t(addr + 4)},
         {"x1", uint32_t(mem_addr)}},
        {{"x3", uint32_t(0x0000'8001u)},
         {"pc", uint32_t(addr + 8)}},
        kRV32RegAccessors);
    spec.AddPrecWrite<uint16_t>(mem_addr, 0x8001u);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV32, LoadWordAndStoreWord_Lw_Sw) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t addr = 0x2000;
  const uint64_t mem_addr = 0x20000;

  // lw x2, 0(x1)
  const auto lw_word =
      riscv::EncodeI(riscv::kOpcodeLoad, /*rd=*/2, /*funct3=*/0x2, /*rs1=*/1,
                     /*imm12=*/0);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr, riscv::Bytes32(lw_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(addr)},
         {"x1", uint32_t(mem_addr)}},
        {{"x2", uint32_t(0x89AB'CDEFu)},
         {"pc", uint32_t(addr + 4)}},
        kRV32RegAccessors);
    spec.AddPrecWrite<uint32_t>(mem_addr, 0x89AB'CDEFu);
    runner.RunTestSpec(spec);
  }

  // sw x2, 4(x1)
  const auto sw_word =
      riscv::EncodeS(riscv::kOpcodeStore, /*funct3=*/0x2, /*rs1=*/1, /*rs2=*/2,
                     /*imm12=*/4);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        addr + 4, riscv::Bytes32(sw_word),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(addr + 4)},
         {"x1", uint32_t(mem_addr)},
         {"x2", uint32_t(0x89AB'CDEFu)}},
        {{"pc", uint32_t(addr + 8)}},
        kRV32RegAccessors);
    spec.AddPostRead<uint32_t>(mem_addr + 4, 0x89AB'CDEFu);
    runner.RunTestSpec(spec);
  }
}

// -- RV32I control flow -------------------------------------------------------

TEST(RISCV32, Branch_BeqTakenAndNotTaken) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // beq x1, x2, +8
  const auto beq_word =
      riscv::EncodeB(riscv::kOpcodeBranch, /*funct3=*/0, /*rs1=*/1, /*rs2=*/2,
                     /*imm13=*/8);

  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0xA000, riscv::Bytes32(beq_word),
        remill::Instruction::Category::kCategoryConditionalBranch,
        {{"pc", uint32_t(0xA000u)},
         {"x1", uint32_t(0x1111u)},
         {"x2", uint32_t(0x1111u)}},
        {{"pc", uint32_t(0xA008u)}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }

  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0xA100, riscv::Bytes32(beq_word),
        remill::Instruction::Category::kCategoryConditionalBranch,
        {{"pc", uint32_t(0xA100u)},
         {"x1", uint32_t(0x1111u)},
         {"x2", uint32_t(0x2222u)}},
        {{"pc", uint32_t(0xA104u)}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV32, Jal_SetsLinkRegisterAndPc) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // jal x5, +8
  const auto jal_word =
      riscv::EncodeJ(riscv::kOpcodeJal, /*rd=*/5, /*imm21=*/8);
  test_runner::TestOutputSpec<RISCVState> spec(
      0xB000, riscv::Bytes32(jal_word),
      remill::Instruction::Category::kCategoryDirectFunctionCall,
      {{"pc", uint32_t(0xB000u)},
       {"x5", uint32_t(0u)}},
      {{"x5", uint32_t(0xB004u)},
       {"pc", uint32_t(0xB008u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, Jalr_ClearsTargetLsbAndSetsLink) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t addr = 0x1000;

  // jalr x5, 0(x2)
  const auto word =
      riscv::EncodeI(riscv::kOpcodeJalr, /*rd=*/5, /*funct3=*/0, /*rs1=*/2,
                     /*imm12=*/0);

  test_runner::TestOutputSpec<RISCVState> spec(
      addr, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryIndirectFunctionCall,
      {{"pc", uint32_t(addr)},
       {"x2", uint32_t(0x2001u)},
       {"x5", uint32_t(0u)}},
      {{"x5", uint32_t(addr + 4)},
       {"pc", uint32_t(0x2000u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, Branches_AllConditions_TakenAndNotTaken) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  struct Case {
    const char *name;
    uint32_t funct3;
    uint32_t rs1;
    uint32_t rs2;
    bool taken;
  };

  const std::vector<Case> cases = {
      {"beq_taken", 0x0, 0x11u, 0x11u, true},
      {"beq_not_taken", 0x0, 0x11u, 0x22u, false},
      {"bne_taken", 0x1, 0x11u, 0x22u, true},
      {"bne_not_taken", 0x1, 0x11u, 0x11u, false},
      {"blt_taken", 0x4, 0xFFFF'FFFFu, 1u, true},
      {"blt_not_taken", 0x4, 2u, 1u, false},
      {"bge_taken", 0x5, 2u, 1u, true},
      {"bge_not_taken", 0x5, 0xFFFF'FFFFu, 1u, false},
      {"bltu_taken", 0x6, 1u, 0xFFFF'FFFFu, true},
      {"bltu_not_taken", 0x6, 0xFFFF'FFFFu, 1u, false},
      {"bgeu_taken", 0x7, 0xFFFF'FFFFu, 1u, true},
      {"bgeu_not_taken", 0x7, 1u, 0xFFFF'FFFFu, false},
  };

  for (const auto &tc : cases) {
    SCOPED_TRACE(tc.name);

    const uint64_t addr = 0x3000;
    const uint64_t target = addr + 8;

    const auto word =
        riscv::EncodeB(riscv::kOpcodeBranch, tc.funct3, /*rs1=*/1, /*rs2=*/2,
                       /*imm13=*/8);

    const uint32_t expected_pc =
        static_cast<uint32_t>(tc.taken ? target : (addr + 4));

    test_runner::TestOutputSpec<RISCVState> spec(
        addr, riscv::Bytes32(word),
        remill::Instruction::Category::kCategoryConditionalBranch,
        {{"pc", uint32_t(addr)},
         {"x1", uint32_t(tc.rs1)},
         {"x2", uint32_t(tc.rs2)}},
        {{"pc", uint32_t(expected_pc)}},
        kRV32RegAccessors);
    runner.RunTestSpec(spec);
  }
}

// -- RV32I system (ecall/ebreak) ----------------------------------------------

TEST(RISCV32, EcallAndEbreak_SetHyperCallMarker) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  test_runner::MemoryHandler mem(llvm::endianness::little);
  RISCVState st = {};

  // ecall => 0x00000073
  const uint64_t ecall_addr = 0xC000;
  st = {};
  st.hyper_call = AsyncHyperCall::kInvalid;
  st.pc.dword = static_cast<uint32_t>(ecall_addr);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_ecall", riscv::Bytes32(0x0000'0073U), ecall_addr, &st,
      &mem);
  EXPECT_EQ(st.hyper_call, AsyncHyperCall::kRISCVSysCall);

  // ebreak => 0x00100073
  const uint64_t ebreak_addr = 0xC100;
  st = {};
  st.hyper_call = AsyncHyperCall::kInvalid;
  st.pc.dword = static_cast<uint32_t>(ebreak_addr);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_ebreak", riscv::Bytes32(0x0010'0073U), ebreak_addr, &st,
      &mem);
  EXPECT_EQ(st.hyper_call, AsyncHyperCall::kRISCVBreak);
}

// -- main ---------------------------------------------------------------------

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  return RUN_ALL_TESTS();
}
