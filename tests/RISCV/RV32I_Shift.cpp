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
#include <remill/OS/OS.h>
#include <test_runner/TestRunner.h>

#include <cstdint>

#include "TestHarness.h"
#include "TestUtil.h"

TEST(RISCV32, Slli_AndRegisterShiftMasking) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  const uint64_t addr = 0x1000;
  test_runner::MemoryHandler mem(llvm::endianness::little);

  // slli x2, x1, 31
  const auto slli_word = riscv::EncodeShiftI32(/*funct3=*/0x1, /*rd=*/2,
                                               /*rs1=*/1, /*shamt=*/31,
                                               /*funct7=*/0x00);
  RISCVState st = {};
  st.pc.dword = static_cast<uint32_t>(addr);
  st.gpr.x1.dword = 1u;

  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_slli_x2_x1_31", riscv::Bytes32(slli_word), addr, &st,
      &mem);

  EXPECT_EQ(st.gpr.x2.dword, 0x8000'0000u);

  // sll x3, x1, x2  with x2=37 should shift by (37 & 31) == 5
  const auto sll_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/3, /*funct3=*/0x1, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x00);
  st.pc.dword = static_cast<uint32_t>(addr + 4);
  st.gpr.x1.dword = 1u;
  st.gpr.x2.dword = 37u;
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_sll_x3_x1_x2_mask", riscv::Bytes32(sll_word), addr + 4,
      &st, &mem);

  EXPECT_EQ(st.gpr.x3.dword, 0x20u);
}

TEST(RISCV32, SrlVsSra_RegisterShift) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  const uint64_t addr = 0x2000;
  test_runner::MemoryHandler mem(llvm::endianness::little);

  RISCVState st = {};
  st.pc.dword = static_cast<uint32_t>(addr);
  st.gpr.x1.dword = 0x8000'0000u;
  st.gpr.x2.dword = 1u;

  // srl x3, x1, x2
  const auto srl_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/3, /*funct3=*/0x5, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x00);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_srl_x3_x1_x2", riscv::Bytes32(srl_word), addr, &st,
      &mem);
  EXPECT_EQ(st.gpr.x3.dword, 0x4000'0000u);

  // sra x4, x1, x2
  const auto sra_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/4, /*funct3=*/0x5, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x20);
  st.pc.dword = static_cast<uint32_t>(addr + 4);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_sra_x4_x1_x2", riscv::Bytes32(sra_word), addr + 4, &st,
      &mem);
  EXPECT_EQ(st.gpr.x4.dword, 0xC000'0000u);
}

