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

TEST(RISCV64, Addiw_SignExtends32BitResult) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV64);

  const uint64_t addr = 0x1000;

  // addiw x2, x0, -1
  const auto word =
      riscv::EncodeI(riscv::kOpcodeOpImm32, /*rd=*/2, /*funct3=*/0, /*rs1=*/0,
                     /*imm12=*/-1);

  RISCVState st = {};
  st.pc.qword = addr;
  st.gpr.x2.qword = 0u;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_addiw_x2_x0_-1", riscv::Bytes32(word), addr, &st, &mem);

  EXPECT_EQ(st.gpr.x2.qword, 0xFFFF'FFFF'FFFF'FFFFULL);
  EXPECT_EQ(st.pc.qword, addr + 4);
}

TEST(RISCV64, Addw_UsesLow32BitsAndSignExtends) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV64);

  const uint64_t addr = 0x2000;

  // addw x3, x1, x2
  const auto word =
      riscv::EncodeR(riscv::kOpcodeOp32, /*rd=*/3, /*funct3=*/0, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x00);

  RISCVState st = {};
  st.pc.qword = addr;
  st.gpr.x1.qword = 0x0000'0000'8000'0000ULL;
  st.gpr.x2.qword = 0u;
  st.gpr.x3.qword = 0u;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_addw_x3_x1_x2", riscv::Bytes32(word), addr, &st, &mem);

  EXPECT_EQ(st.gpr.x3.qword, 0xFFFF'FFFF'8000'0000ULL);
  EXPECT_EQ(st.pc.qword, addr + 4);
}

