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

TEST(RISCV32, LoadHalfwordSignAndZeroExtension_Lh_Lhu) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  const uint64_t addr = 0x1000;
  const uint64_t mem_addr = 0x10000;

  RISCVState st = {};
  st.pc.dword = static_cast<uint32_t>(addr);
  st.gpr.x1.dword = static_cast<uint32_t>(mem_addr);

  test_runner::MemoryHandler mem(llvm::endianness::little);
  mem.WriteMemory<uint16_t>(mem_addr, 0x8001u);

  // lh x2, 0(x1)
  const auto lh_word =
      riscv::EncodeI(riscv::kOpcodeLoad, /*rd=*/2, /*funct3=*/0x1, /*rs1=*/1,
                     /*imm12=*/0);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_lh_x2_0_x1", riscv::Bytes32(lh_word), addr, &st, &mem);
  EXPECT_EQ(st.gpr.x2.dword, 0xFFFF'8001u);

  // lhu x3, 0(x1)
  const auto lhu_word =
      riscv::EncodeI(riscv::kOpcodeLoad, /*rd=*/3, /*funct3=*/0x5, /*rs1=*/1,
                     /*imm12=*/0);
  st.pc.dword = static_cast<uint32_t>(addr + 4);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_lhu_x3_0_x1", riscv::Bytes32(lhu_word), addr + 4, &st,
      &mem);
  EXPECT_EQ(st.gpr.x3.dword, 0x0000'8001u);
}

TEST(RISCV32, LoadWordAndStoreWord_Lw_Sw) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  const uint64_t addr = 0x2000;
  const uint64_t mem_addr = 0x20000;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  mem.WriteMemory<uint32_t>(mem_addr, 0x89AB'CDEFu);

  // lw x2, 0(x1)
  const auto lw_word =
      riscv::EncodeI(riscv::kOpcodeLoad, /*rd=*/2, /*funct3=*/0x2, /*rs1=*/1,
                     /*imm12=*/0);

  RISCVState st = {};
  st.pc.dword = static_cast<uint32_t>(addr);
  st.gpr.x1.dword = static_cast<uint32_t>(mem_addr);

  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_lw_x2_0_x1", riscv::Bytes32(lw_word), addr, &st, &mem);

  EXPECT_EQ(st.gpr.x2.dword, 0x89AB'CDEFu);
  EXPECT_EQ(st.pc.dword, static_cast<uint32_t>(addr + 4));

  // sw x2, 4(x1)
  const auto sw_word =
      riscv::EncodeS(riscv::kOpcodeStore, /*funct3=*/0x2, /*rs1=*/1, /*rs2=*/2,
                     /*imm12=*/4);
  st.pc.dword = static_cast<uint32_t>(addr + 4);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_sw_x2_4_x1", riscv::Bytes32(sw_word), addr + 4, &st,
      &mem);

  const auto &mem_map = mem.GetMemory();
  EXPECT_EQ(mem_map.at(mem_addr + 4), 0xEFu);
  EXPECT_EQ(mem_map.at(mem_addr + 5), 0xCDu);
  EXPECT_EQ(mem_map.at(mem_addr + 6), 0xABu);
  EXPECT_EQ(mem_map.at(mem_addr + 7), 0x89u);
}

