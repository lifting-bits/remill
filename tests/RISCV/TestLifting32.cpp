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
#include <llvm/Transforms/Utils/Cloning.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/BC/Optimizer.h>
#include <remill/OS/OS.h>
#include <test_runner/TestRunner.h>

#include "TestUtil.h"
#include "TestHarness.h"

#include <cstdint>
#include <string>

TEST(RISCV32, X0WriteIsIgnored_Addi) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  const uint64_t addr = 0x1000;

  // addi x0, x0, 1  => 0x00100013
  RISCVState st = {};
  st.pc.dword = static_cast<uint32_t>(addr);
  st.gpr.x0.dword = 0x12345678u;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_addi_x0_x0_1", riscv::Bytes32(0x00100013U), addr, &st,
      &mem);

  EXPECT_EQ(st.gpr.x0.dword, 0u);
}

TEST(RISCV32, X0ReadAsZero_Addi) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  const uint64_t addr = 0x2000;

  // addi x1, x0, 5  => 0x00500093
  RISCVState st = {};
  st.pc.dword = static_cast<uint32_t>(addr);

  // Even if the test harness starts with garbage in x0, architectural semantics
  // require reads of x0 to produce 0.
  st.gpr.x0.dword = 0xDEADBEEFu;
  st.gpr.x1.dword = 0u;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_addi_x1_x0_5", riscv::Bytes32(0x00500093U), addr, &st,
      &mem);

  EXPECT_EQ(st.gpr.x0.dword, 0u);
  EXPECT_EQ(st.gpr.x1.dword, 5u);
}

TEST(RISCV32, Addi_NegativeImmediate) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  const uint64_t addr = 0x3000;

  // addi x1, x0, -1
  const auto word = riscv::EncodeI(riscv::kOpcodeOpImm, /*rd=*/1, /*funct3=*/0,
                                   /*rs1=*/0, /*imm12=*/-1);

  RISCVState st = {};
  st.pc.dword = static_cast<uint32_t>(addr);
  st.gpr.x1.dword = 0u;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_addi_x1_x0_-1", riscv::Bytes32(word), addr, &st, &mem);

  EXPECT_EQ(st.gpr.x1.dword, 0xFFFF'FFFFu);
  EXPECT_EQ(st.pc.dword, static_cast<uint32_t>(addr + 4));
}

TEST(RISCV32, Add_Sub) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  const uint64_t addr = 0x4000;

  // add x3, x1, x2
  const auto add_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/3, /*funct3=*/0, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x00);

  RISCVState st = {};
  st.pc.dword = static_cast<uint32_t>(addr);
  st.gpr.x1.dword = 1u;
  st.gpr.x2.dword = 2u;
  st.gpr.x3.dword = 0u;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_add_x3_x1_x2", riscv::Bytes32(add_word), addr, &st,
      &mem);

  EXPECT_EQ(st.gpr.x3.dword, 3u);
  EXPECT_EQ(st.pc.dword, static_cast<uint32_t>(addr + 4));

  // sub x4, x2, x1
  const auto sub_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/4, /*funct3=*/0, /*rs1=*/2,
                     /*rs2=*/1, /*funct7=*/0x20);

  st.pc.dword = static_cast<uint32_t>(addr + 4);
  st.gpr.x4.dword = 0u;
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_sub_x4_x2_x1", riscv::Bytes32(sub_word), addr + 4, &st,
      &mem);

  EXPECT_EQ(st.gpr.x4.dword, 1u);
  EXPECT_EQ(st.pc.dword, static_cast<uint32_t>(addr + 8));
}

TEST(RISCV32, And_Or_Xor_Immediate) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  const uint64_t addr = 0x5000;
  RISCVState st = {};
  st.pc.dword = static_cast<uint32_t>(addr);
  st.gpr.x1.dword = 0xF0F0'00FFu;

  test_runner::MemoryHandler mem(llvm::endianness::little);

  // andi x2, x1, 0x0F0
  const auto andi_word =
      riscv::EncodeI(riscv::kOpcodeOpImm, /*rd=*/2, /*funct3=*/0x7, /*rs1=*/1,
                     /*imm12=*/0x0F0);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_andi_x2_x1_0f0", riscv::Bytes32(andi_word), addr, &st,
      &mem);
  EXPECT_EQ(st.gpr.x2.dword, 0x0000'00F0u);

  // ori x3, x1, 0x00F
  const auto ori_word =
      riscv::EncodeI(riscv::kOpcodeOpImm, /*rd=*/3, /*funct3=*/0x6, /*rs1=*/1,
                     /*imm12=*/0x00F);
  st.pc.dword = static_cast<uint32_t>(addr + 4);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_ori_x3_x1_00f", riscv::Bytes32(ori_word), addr + 4, &st,
      &mem);
  EXPECT_EQ(st.gpr.x3.dword, 0xF0F0'00FFu);

  // xori x4, x1, 0x0FF
  const auto xori_word =
      riscv::EncodeI(riscv::kOpcodeOpImm, /*rd=*/4, /*funct3=*/0x4, /*rs1=*/1,
                     /*imm12=*/0x0FF);
  st.pc.dword = static_cast<uint32_t>(addr + 8);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_xori_x4_x1_0ff", riscv::Bytes32(xori_word), addr + 8,
      &st, &mem);
  EXPECT_EQ(st.gpr.x4.dword, 0xF0F0'0000u);
}

TEST(RISCV32, Slt_Sltu_SignedVsUnsigned) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  const uint64_t addr = 0x6000;
  RISCVState st = {};
  st.pc.dword = static_cast<uint32_t>(addr);

  // x1 = -1, x2 = 1
  st.gpr.x1.dword = 0xFFFF'FFFFu;
  st.gpr.x2.dword = 1u;

  test_runner::MemoryHandler mem(llvm::endianness::little);

  // slt x3, x1, x2  (signed)
  const auto slt_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/3, /*funct3=*/0x2, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x00);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_slt_x3_x1_x2", riscv::Bytes32(slt_word), addr, &st,
      &mem);
  EXPECT_EQ(st.gpr.x3.dword, 1u);

  // sltu x4, x1, x2 (unsigned)
  const auto sltu_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/4, /*funct3=*/0x3, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x00);
  st.pc.dword = static_cast<uint32_t>(addr + 4);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_sltu_x4_x1_x2", riscv::Bytes32(sltu_word), addr + 4,
      &st, &mem);
  EXPECT_EQ(st.gpr.x4.dword, 0u);
}

TEST(RISCV32, ShiftImmediate_SrliVsSrai) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  const uint64_t addr = 0x7000;
  RISCVState st = {};
  st.pc.dword = static_cast<uint32_t>(addr);
  st.gpr.x1.dword = 0x8000'0000u;

  test_runner::MemoryHandler mem(llvm::endianness::little);

  // srli x2, x1, 1
  const auto srli_word = riscv::EncodeShiftI32(/*funct3=*/0x5, /*rd=*/2,
                                               /*rs1=*/1, /*shamt=*/1,
                                               /*funct7=*/0x00);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_srli_x2_x1_1", riscv::Bytes32(srli_word), addr, &st,
      &mem);
  EXPECT_EQ(st.gpr.x2.dword, 0x4000'0000u);

  // srai x3, x1, 1
  const auto srai_word = riscv::EncodeShiftI32(/*funct3=*/0x5, /*rd=*/3,
                                               /*rs1=*/1, /*shamt=*/1,
                                               /*funct7=*/0x20);
  st.pc.dword = static_cast<uint32_t>(addr + 4);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_srai_x3_x1_1", riscv::Bytes32(srai_word), addr + 4, &st,
      &mem);
  EXPECT_EQ(st.gpr.x3.dword, 0xC000'0000u);
}

TEST(RISCV32, LoadSignAndZeroExtension_Lb_Lbu) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  const uint64_t addr = 0x8000;
  const uint64_t mem_addr = 0x10000;

  RISCVState st = {};
  st.pc.dword = static_cast<uint32_t>(addr);
  st.gpr.x1.dword = static_cast<uint32_t>(mem_addr);

  test_runner::MemoryHandler mem(llvm::endianness::little);
  mem.WriteMemory<uint8_t>(mem_addr, 0x80u);

  // lb x2, 0(x1)
  const auto lb_word = riscv::EncodeI(riscv::kOpcodeLoad, /*rd=*/2, /*funct3=*/0,
                                      /*rs1=*/1, /*imm12=*/0);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_lb_x2_0_x1", riscv::Bytes32(lb_word), addr, &st, &mem);
  EXPECT_EQ(st.gpr.x2.dword, 0xFFFF'FF80u);

  // lbu x3, 0(x1)
  const auto lbu_word =
      riscv::EncodeI(riscv::kOpcodeLoad, /*rd=*/3, /*funct3=*/0x4, /*rs1=*/1,
                     /*imm12=*/0);
  st.pc.dword = static_cast<uint32_t>(addr + 4);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_lbu_x3_0_x1", riscv::Bytes32(lbu_word), addr + 4, &st,
      &mem);
  EXPECT_EQ(st.gpr.x3.dword, 0x0000'0080u);
}

TEST(RISCV32, StoreByteAndHalfword_Sb_Sh) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  const uint64_t addr = 0x9000;
  const uint64_t mem_addr = 0x20000;

  RISCVState st = {};
  st.pc.dword = static_cast<uint32_t>(addr);
  st.gpr.x1.dword = static_cast<uint32_t>(mem_addr);
  st.gpr.x2.dword = 0xA1B2'C3D4u;

  test_runner::MemoryHandler mem(llvm::endianness::little);

  // sb x2, 0(x1)
  const auto sb_word =
      riscv::EncodeS(riscv::kOpcodeStore, /*funct3=*/0, /*rs1=*/1, /*rs2=*/2,
                     /*imm12=*/0);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_sb_x2_0_x1", riscv::Bytes32(sb_word), addr, &st, &mem);

  const auto &mem_map = mem.GetMemory();
  auto it = mem_map.find(mem_addr);
  ASSERT_TRUE(it != mem_map.end());
  EXPECT_EQ(it->second, 0xD4u);

  // sh x2, 2(x1)
  const auto sh_word =
      riscv::EncodeS(riscv::kOpcodeStore, /*funct3=*/0x1, /*rs1=*/1, /*rs2=*/2,
                     /*imm12=*/2);
  st.pc.dword = static_cast<uint32_t>(addr + 4);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_sh_x2_2_x1", riscv::Bytes32(sh_word), addr + 4, &st,
      &mem);

  auto it0 = mem_map.find(mem_addr + 2);
  auto it1 = mem_map.find(mem_addr + 3);
  ASSERT_TRUE(it0 != mem_map.end());
  ASSERT_TRUE(it1 != mem_map.end());
  EXPECT_EQ(it0->second, 0xD4u);
  EXPECT_EQ(it1->second, 0xC3u);
}

TEST(RISCV32, Branch_BeqTakenAndNotTaken) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  const uint64_t addr = 0xA000;
  RISCVState st = {};
  st.pc.dword = static_cast<uint32_t>(addr);

  test_runner::MemoryHandler mem(llvm::endianness::little);

  // beq x1, x2, +8
  const auto beq_word =
      riscv::EncodeB(riscv::kOpcodeBranch, /*funct3=*/0, /*rs1=*/1, /*rs2=*/2,
                     /*imm13=*/8);

  // Taken path.
  st.gpr.x1.dword = 0x1111u;
  st.gpr.x2.dword = 0x1111u;
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_beq_taken", riscv::Bytes32(beq_word), addr, &st, &mem);
  EXPECT_EQ(st.pc.dword, static_cast<uint32_t>(addr + 8));

  // Not-taken path.
  st.pc.dword = static_cast<uint32_t>(addr + 0x100);
  st.gpr.x1.dword = 0x1111u;
  st.gpr.x2.dword = 0x2222u;
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_beq_not_taken", riscv::Bytes32(beq_word), addr + 0x100,
      &st, &mem);
  EXPECT_EQ(st.pc.dword, static_cast<uint32_t>(addr + 0x104));
}

TEST(RISCV32, Jal_SetsLinkRegisterAndPc) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  const uint64_t addr = 0xB000;
  RISCVState st = {};
  st.pc.dword = static_cast<uint32_t>(addr);
  st.gpr.x5.dword = 0u;

  test_runner::MemoryHandler mem(llvm::endianness::little);

  // jal x5, +8
  const auto jal_word = riscv::EncodeJ(riscv::kOpcodeJal, /*rd=*/5, /*imm21=*/8);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_jal_x5_plus8", riscv::Bytes32(jal_word), addr, &st,
      &mem);

  EXPECT_EQ(st.gpr.x5.dword, static_cast<uint32_t>(addr + 4));
  EXPECT_EQ(st.pc.dword, static_cast<uint32_t>(addr + 8));
}

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

TEST(RISCV32, CompressedAddi_IncrementsPcBy2) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  const uint64_t addr = 0xD000;
  RISCVState st = {};
  st.pc.dword = static_cast<uint32_t>(addr);
  st.gpr.x1.dword = 41u;

  test_runner::MemoryHandler mem(llvm::endianness::little);

  // c.addi x1, 1  => 0x0085
  const auto half = riscv::EncodeCAddi(/*rd=*/1, /*imm6=*/1);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_c_addi_x1_1", riscv::Bytes16(half), addr, &st, &mem);

  EXPECT_EQ(st.gpr.x1.dword, 42u);
  EXPECT_EQ(st.pc.dword, static_cast<uint32_t>(addr + 2));
}
