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
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>
#include <test_runner/TestRunner.h>

#include <cstdint>
#include <string>
#include "TestUtil.h"
#include "TestHarness.h"

TEST(RISCV64, X0WriteIsIgnored_Addi) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV64);

  const uint64_t addr = 0x1000;

  // addi x0, x0, 1  => 0x00100013
  RISCVState st = {};
  st.pc.qword = addr;
  st.gpr.x0.qword = 0x0123456789ABCDEFu;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_addi_x0_x0_1", riscv::Bytes32(0x00100013U), addr, &st,
      &mem);

  EXPECT_EQ(st.gpr.x0.qword, 0u);
}

TEST(RISCV64, X0ReadAsZero_Addi) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV64);

  const uint64_t addr = 0x2000;

  // addi x1, x0, 5  => 0x00500093
  RISCVState st = {};
  st.pc.qword = addr;
  st.gpr.x0.qword = 0xDEADBEEFu;
  st.gpr.x1.qword = 0u;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_addi_x1_x0_5", riscv::Bytes32(0x00500093U), addr, &st,
      &mem);

  EXPECT_EQ(st.gpr.x0.qword, 0u);
  EXPECT_EQ(st.gpr.x1.qword, 5u);
}

TEST(RISCV64, PcIs64Bit_AddiAtHighAddress) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV64);

  const uint64_t addr = 0x1234'5678'9000ULL;

  // addi x1, x0, 1
  const auto word = riscv::EncodeI(riscv::kOpcodeOpImm, /*rd=*/1, /*funct3=*/0,
                                   /*rs1=*/0, /*imm12=*/1);

  RISCVState st = {};
  st.pc.qword = addr;
  st.gpr.x1.qword = 0u;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_addi_x1_x0_1_highpc", riscv::Bytes32(word), addr, &st,
      &mem);

  EXPECT_EQ(st.gpr.x1.qword, 1u);
  EXPECT_EQ(st.pc.qword, addr + 4);
}

TEST(RISCV64, Addi_NegativeImmediate) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV64);

  const uint64_t addr = 0x3000;

  // addi x1, x0, -1
  const auto word = riscv::EncodeI(riscv::kOpcodeOpImm, /*rd=*/1, /*funct3=*/0,
                                   /*rs1=*/0, /*imm12=*/-1);

  RISCVState st = {};
  st.pc.qword = addr;
  st.gpr.x1.qword = 0u;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_addi_x1_x0_-1", riscv::Bytes32(word), addr, &st, &mem);

  EXPECT_EQ(st.gpr.x1.qword, 0xFFFF'FFFF'FFFF'FFFFULL);
  EXPECT_EQ(st.pc.qword, addr + 4);
}

TEST(RISCV64, Add_Sub) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV64);

  const uint64_t addr = 0x4000;

  // add x3, x1, x2
  const auto add_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/3, /*funct3=*/0, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x00);

  RISCVState st = {};
  st.pc.qword = addr;
  st.gpr.x1.qword = 1u;
  st.gpr.x2.qword = 2u;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_add_x3_x1_x2", riscv::Bytes32(add_word), addr, &st,
      &mem);

  EXPECT_EQ(st.gpr.x3.qword, 3u);
  EXPECT_EQ(st.pc.qword, addr + 4);

  // sub x4, x2, x1
  const auto sub_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/4, /*funct3=*/0, /*rs1=*/2,
                     /*rs2=*/1, /*funct7=*/0x20);

  st.pc.qword = addr + 4;
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_sub_x4_x2_x1", riscv::Bytes32(sub_word), addr + 4, &st,
      &mem);

  EXPECT_EQ(st.gpr.x4.qword, 1u);
  EXPECT_EQ(st.pc.qword, addr + 8);
}

TEST(RISCV64, Slt_Sltu_SignedVsUnsigned) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV64);

  const uint64_t addr = 0x6000;
  RISCVState st = {};
  st.pc.qword = addr;

  // x1 = -1, x2 = 1
  st.gpr.x1.qword = 0xFFFF'FFFF'FFFF'FFFFULL;
  st.gpr.x2.qword = 1u;

  test_runner::MemoryHandler mem(llvm::endianness::little);

  // slt x3, x1, x2  (signed)
  const auto slt_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/3, /*funct3=*/0x2, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x00);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_slt_x3_x1_x2", riscv::Bytes32(slt_word), addr, &st,
      &mem);
  EXPECT_EQ(st.gpr.x3.qword, 1u);

  // sltu x4, x1, x2 (unsigned)
  const auto sltu_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/4, /*funct3=*/0x3, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x00);
  st.pc.qword = addr + 4;
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_sltu_x4_x1_x2", riscv::Bytes32(sltu_word), addr + 4,
      &st, &mem);
  EXPECT_EQ(st.gpr.x4.qword, 0u);
}

TEST(RISCV64, ShiftImmediate_SrliVsSrai) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV64);

  const uint64_t addr = 0x7000;
  RISCVState st = {};
  st.pc.qword = addr;
  st.gpr.x1.qword = 0x8000'0000'0000'0000ULL;

  test_runner::MemoryHandler mem(llvm::endianness::little);

  // srli x2, x1, 1
  const auto srli_word = riscv::EncodeShiftI64(/*funct3=*/0x5, /*rd=*/2,
                                               /*rs1=*/1, /*shamt=*/1,
                                               /*funct6=*/0x00);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_srli_x2_x1_1", riscv::Bytes32(srli_word), addr, &st,
      &mem);
  EXPECT_EQ(st.gpr.x2.qword, 0x4000'0000'0000'0000ULL);

  // srai x3, x1, 1
  const auto srai_word = riscv::EncodeShiftI64(/*funct3=*/0x5, /*rd=*/3,
                                               /*rs1=*/1, /*shamt=*/1,
                                               /*funct6=*/0x10);
  st.pc.qword = addr + 4;
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_srai_x3_x1_1", riscv::Bytes32(srai_word), addr + 4, &st,
      &mem);
  EXPECT_EQ(st.gpr.x3.qword, 0xC000'0000'0000'0000ULL);
}

TEST(RISCV64, LoadSignExtension_LwAndLwu) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV64);

  const uint64_t addr = 0x8000;
  const uint64_t mem_addr = 0x10000;

  RISCVState st = {};
  st.pc.qword = addr;
  st.gpr.x1.qword = mem_addr;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  mem.WriteMemory<uint32_t>(mem_addr, 0x8000'0000u);

  // lw x2, 0(x1)  => sign-extends
  const auto lw_word = riscv::EncodeI(riscv::kOpcodeLoad, /*rd=*/2, /*funct3=*/0x2,
                                      /*rs1=*/1, /*imm12=*/0);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_lw_x2_0_x1", riscv::Bytes32(lw_word), addr, &st, &mem);
  EXPECT_EQ(st.gpr.x2.qword, 0xFFFF'FFFF'8000'0000ULL);

  // lwu x3, 0(x1) => zero-extends
  const auto lwu_word =
      riscv::EncodeI(riscv::kOpcodeLoad, /*rd=*/3, /*funct3=*/0x6, /*rs1=*/1,
                     /*imm12=*/0);
  st.pc.qword = addr + 4;
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_lwu_x3_0_x1", riscv::Bytes32(lwu_word), addr + 4, &st,
      &mem);
  EXPECT_EQ(st.gpr.x3.qword, 0x0000'0000'8000'0000ULL);
}

TEST(RISCV64, StoreDoubleword_Sd) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV64);

  const uint64_t addr = 0x9000;
  const uint64_t mem_addr = 0x20000;

  RISCVState st = {};
  st.pc.qword = addr;
  st.gpr.x1.qword = mem_addr;
  st.gpr.x2.qword = 0x1122'3344'5566'7788ULL;

  test_runner::MemoryHandler mem(llvm::endianness::little);

  // sd x2, 0(x1)
  const auto sd_word =
      riscv::EncodeS(riscv::kOpcodeStore, /*funct3=*/0x3, /*rs1=*/1, /*rs2=*/2,
                     /*imm12=*/0);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_sd_x2_0_x1", riscv::Bytes32(sd_word), addr, &st, &mem);

  const auto &mem_map = mem.GetMemory();
  ASSERT_EQ(mem_map.at(mem_addr + 0), 0x88u);
  ASSERT_EQ(mem_map.at(mem_addr + 1), 0x77u);
  ASSERT_EQ(mem_map.at(mem_addr + 2), 0x66u);
  ASSERT_EQ(mem_map.at(mem_addr + 3), 0x55u);
  ASSERT_EQ(mem_map.at(mem_addr + 4), 0x44u);
  ASSERT_EQ(mem_map.at(mem_addr + 5), 0x33u);
  ASSERT_EQ(mem_map.at(mem_addr + 6), 0x22u);
  ASSERT_EQ(mem_map.at(mem_addr + 7), 0x11u);
}

TEST(RISCV64, Jal_SetsLinkRegisterAndPc) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV64);

  const uint64_t addr = 0xB000;
  RISCVState st = {};
  st.pc.qword = addr;
  st.gpr.x5.qword = 0u;

  test_runner::MemoryHandler mem(llvm::endianness::little);

  // jal x5, +8
  const auto jal_word = riscv::EncodeJ(riscv::kOpcodeJal, /*rd=*/5, /*imm21=*/8);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_jal_x5_plus8", riscv::Bytes32(jal_word), addr, &st,
      &mem);

  EXPECT_EQ(st.gpr.x5.qword, addr + 4);
  EXPECT_EQ(st.pc.qword, addr + 8);
}

TEST(RISCV64, EcallAndEbreak_SetHyperCallMarker) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV64);

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

TEST(RISCV64, CompressedAddi_IncrementsPcBy2) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV64);

  const uint64_t addr = 0xD000;
  RISCVState st = {};
  st.pc.qword = addr;
  st.gpr.x1.qword = 41u;

  test_runner::MemoryHandler mem(llvm::endianness::little);

  // c.addi x1, 1  => 0x0085
  const auto half = riscv::EncodeCAddi(/*rd=*/1, /*imm6=*/1);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_c_addi_x1_1", riscv::Bytes16(half), addr, &st, &mem);

  EXPECT_EQ(st.gpr.x1.qword, 42u);
  EXPECT_EQ(st.pc.qword, addr + 2);
}
