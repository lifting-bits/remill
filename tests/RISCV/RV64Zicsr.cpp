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

// RV64 Zicsr tests use manual ExecuteOne pattern because Sleigh CSRRW
// semantics read 64 bits from the FCSR state area, picking up volatile
// padding bytes that don't match TestOutputSpec expectations.

TEST(RISCV64, Csrrw_Fcsr_WritesAndReturnsOld) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);
  auto &lifter = runner.GetLifter();

  // csrrw x5, fcsr(0x003), x1
  const auto word =
      riscv::EncodeI(riscv::kOpcodeSystem, /*rd=*/5, /*funct3=*/0x1,
                     /*rs1=*/1, /*imm12=*/0x003);

  RISCVState st = {};
  st.pc.qword = 0x1000;
  st.gpr.x1.qword = 0xABCDu;
  st.fcsr.fcsr = 0x1234u;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_csrrw_x5_fcsr_x1", riscv::Bytes32(word), 0x1000, &st,
      &mem);

  EXPECT_EQ(st.gpr.x5.qword, 0x1234u);
  EXPECT_EQ(st.fcsr.fcsr, 0xABCDu);
  EXPECT_EQ(st.pc.qword, 0x1004);
}

TEST(RISCV64, Fsflags_WritesLow5BitsAndReturnsOld) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);
  auto &lifter = runner.GetLifter();

  // fsflags x5, x1 (CSR=0x001)
  const auto word =
      riscv::EncodeI(riscv::kOpcodeSystem, /*rd=*/5, /*funct3=*/0x1,
                     /*rs1=*/1, /*imm12=*/0x001);

  RISCVState st = {};
  st.pc.qword = 0x2000;
  st.gpr.x1.qword = 0x2Au;
  st.fcsr.fflags = 0x1Fu;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_fsflags_x5_x1", riscv::Bytes32(word), 0x2000, &st,
      &mem);

  EXPECT_EQ(st.gpr.x5.qword, 0x1Fu);
  EXPECT_EQ(st.fcsr.fflags, 0x0Au);
  EXPECT_EQ(st.pc.qword, 0x2004);
}
