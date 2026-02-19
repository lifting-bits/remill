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
#include <remill/Arch/Name.h>

#include "RISCVTestSpec.h"
#include "TestUtil.h"

TEST(RISCV32, Csrrw_Fcsr_WritesAndReturnsOld) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);
  auto &lifter = runner.GetLifter();

  // csrrw x5, fcsr(0x003), x1
  const auto word =
      riscv::EncodeI(riscv::kOpcodeSystem, /*rd=*/5, /*funct3=*/0x1,
                     /*rs1=*/1, /*imm12=*/0x003);

  RISCVState st = {};
  st.pc.dword = 0x1000u;
  st.gpr.x1.dword = 0xABCDu;
  st.fcsr.fcsr = 0x1234u;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_csrrw_x5_fcsr_x1", riscv::Bytes32(word), 0x1000, &st,
      &mem);

  EXPECT_EQ(st.gpr.x5.dword, 0x1234u);
  EXPECT_EQ(st.fcsr.fcsr, 0xABCDu);
  EXPECT_EQ(st.pc.dword, 0x1004u);
}

TEST(RISCV32, Fsflags_WritesLow5BitsAndReturnsOld) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);
  auto &lifter = runner.GetLifter();

  // fsflags x5, x1 (CSR=0x001)
  const auto word =
      riscv::EncodeI(riscv::kOpcodeSystem, /*rd=*/5, /*funct3=*/0x1,
                     /*rs1=*/1, /*imm12=*/0x001);

  RISCVState st = {};
  st.pc.dword = 0x2000u;
  st.gpr.x1.dword = 0x2Au;
  st.fcsr.fflags = 0x1Fu;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_fsflags_x5_x1", riscv::Bytes32(word), 0x2000, &st,
      &mem);

  EXPECT_EQ(st.gpr.x5.dword, 0x1Fu);
  EXPECT_EQ(st.fcsr.fflags, 0x0Au);
  EXPECT_EQ(st.pc.dword, 0x2004u);
}

TEST(RISCV32, Csrrs_Fcsr_SetsBitsAndReturnsOld) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);
  auto &lifter = runner.GetLifter();

  // csrrs x5, fcsr(0x003), x1
  const auto word =
      riscv::EncodeI(riscv::kOpcodeSystem, /*rd=*/5, /*funct3=*/0x2,
                     /*rs1=*/1, /*imm12=*/0x003);

  RISCVState st = {};
  st.pc.dword = 0x1000u;
  st.gpr.x1.dword = 0x00F0u;
  st.fcsr.fcsr = 0x000Fu;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_csrrs_x5_fcsr_x1", riscv::Bytes32(word), 0x1000, &st,
      &mem);

  EXPECT_EQ(st.gpr.x5.dword, 0x000Fu);
  EXPECT_EQ(st.fcsr.fcsr, 0x00FFu);
  EXPECT_EQ(st.pc.dword, 0x1004u);
}

TEST(RISCV32, Csrrc_Fcsr_ClearsBitsAndReturnsOld) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);
  auto &lifter = runner.GetLifter();

  // csrrc x5, fcsr(0x003), x1
  const auto word =
      riscv::EncodeI(riscv::kOpcodeSystem, /*rd=*/5, /*funct3=*/0x3,
                     /*rs1=*/1, /*imm12=*/0x003);

  RISCVState st = {};
  st.pc.dword = 0x1000u;
  st.gpr.x1.dword = 0x000Fu;
  st.fcsr.fcsr = 0x00FFu;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_csrrc_x5_fcsr_x1", riscv::Bytes32(word), 0x1000, &st,
      &mem);

  EXPECT_EQ(st.gpr.x5.dword, 0x00FFu);
  EXPECT_EQ(st.fcsr.fcsr, 0x00F0u);
  EXPECT_EQ(st.pc.dword, 0x1004u);
}

TEST(RISCV32, Csrrwi_Fcsr_WritesImmAndReturnsOld) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);
  auto &lifter = runner.GetLifter();

  // csrrwi x5, fcsr(0x003), 0x1A
  // uimm = 0x1A (26), stored in rs1 field
  const auto word =
      riscv::EncodeI(riscv::kOpcodeSystem, /*rd=*/5, /*funct3=*/0x5,
                     /*rs1=*/0x1A, /*imm12=*/0x003);

  RISCVState st = {};
  st.pc.dword = 0x1000u;
  st.fcsr.fcsr = 0x00ABu;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_csrrwi_x5_fcsr_0x1a", riscv::Bytes32(word), 0x1000,
      &st, &mem);

  EXPECT_EQ(st.gpr.x5.dword, 0x00ABu);
  EXPECT_EQ(st.fcsr.fcsr, 0x001Au);
  EXPECT_EQ(st.pc.dword, 0x1004u);
}

TEST(RISCV32, Csrrsi_Fcsr_SetsBitsWithImmAndReturnsOld) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);
  auto &lifter = runner.GetLifter();

  // csrrsi x5, fcsr(0x003), 0x05
  // uimm = 5, stored in rs1 field
  const auto word =
      riscv::EncodeI(riscv::kOpcodeSystem, /*rd=*/5, /*funct3=*/0x6,
                     /*rs1=*/0x05, /*imm12=*/0x003);

  RISCVState st = {};
  st.pc.dword = 0x1000u;
  st.fcsr.fcsr = 0x00F0u;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_csrrsi_x5_fcsr_5", riscv::Bytes32(word), 0x1000, &st,
      &mem);

  EXPECT_EQ(st.gpr.x5.dword, 0x00F0u);
  EXPECT_EQ(st.fcsr.fcsr, 0x00F5u);
  EXPECT_EQ(st.pc.dword, 0x1004u);
}

TEST(RISCV32, Csrrci_Fcsr_ClearsBitsWithImmAndReturnsOld) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);
  auto &lifter = runner.GetLifter();

  // csrrci x5, fcsr(0x003), 0x0F
  // uimm = 15, stored in rs1 field
  const auto word =
      riscv::EncodeI(riscv::kOpcodeSystem, /*rd=*/5, /*funct3=*/0x7,
                     /*rs1=*/0x0F, /*imm12=*/0x003);

  RISCVState st = {};
  st.pc.dword = 0x1000u;
  st.fcsr.fcsr = 0x00FFu;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_csrrci_x5_fcsr_0xf", riscv::Bytes32(word), 0x1000,
      &st, &mem);

  EXPECT_EQ(st.gpr.x5.dword, 0x00FFu);
  EXPECT_EQ(st.fcsr.fcsr, 0x00F0u);
  EXPECT_EQ(st.pc.dword, 0x1004u);
}
