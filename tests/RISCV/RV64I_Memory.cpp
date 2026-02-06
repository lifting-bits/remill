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

TEST(RISCV64, LoadDoubleword_Ld) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV64);

  const uint64_t addr = 0x1000;
  const uint64_t mem_addr = 0x10000;

  RISCVState st = {};
  st.pc.qword = addr;
  st.gpr.x1.qword = mem_addr;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  mem.WriteMemory<uint64_t>(mem_addr, 0x1122'3344'5566'7788ULL);

  // ld x2, 0(x1)
  const auto ld_word =
      riscv::EncodeI(riscv::kOpcodeLoad, /*rd=*/2, /*funct3=*/0x3, /*rs1=*/1,
                     /*imm12=*/0);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_ld_x2_0_x1", riscv::Bytes32(ld_word), addr, &st, &mem);

  EXPECT_EQ(st.gpr.x2.qword, 0x1122'3344'5566'7788ULL);
  EXPECT_EQ(st.pc.qword, addr + 4);
}

TEST(RISCV64, LoadHalfwordSignAndZeroExtension_Lh_Lhu) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV64);

  const uint64_t addr = 0x2000;
  const uint64_t mem_addr = 0x20000;

  RISCVState st = {};
  st.pc.qword = addr;
  st.gpr.x1.qword = mem_addr;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  mem.WriteMemory<uint16_t>(mem_addr, 0x8001u);

  // lh x2, 0(x1)
  const auto lh_word =
      riscv::EncodeI(riscv::kOpcodeLoad, /*rd=*/2, /*funct3=*/0x1, /*rs1=*/1,
                     /*imm12=*/0);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_lh_x2_0_x1", riscv::Bytes32(lh_word), addr, &st, &mem);
  EXPECT_EQ(st.gpr.x2.qword, 0xFFFF'FFFF'FFFF'8001ULL);

  // lhu x3, 0(x1)
  const auto lhu_word =
      riscv::EncodeI(riscv::kOpcodeLoad, /*rd=*/3, /*funct3=*/0x5, /*rs1=*/1,
                     /*imm12=*/0);
  st.pc.qword = addr + 4;
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_lhu_x3_0_x1", riscv::Bytes32(lhu_word), addr + 4, &st,
      &mem);
  EXPECT_EQ(st.gpr.x3.qword, 0x0000'0000'0000'8001ULL);
}

