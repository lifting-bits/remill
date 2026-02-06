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
#include <vector>

#include "TestHarness.h"
#include "TestUtil.h"

TEST(RISCV64, Jalr_ClearsTargetLsbAndSetsLink) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV64);

  const uint64_t addr = 0x1000;

  // jalr x5, 0(x2)
  const auto word =
      riscv::EncodeI(riscv::kOpcodeJalr, /*rd=*/5, /*funct3=*/0, /*rs1=*/2,
                     /*imm12=*/0);

  RISCVState st = {};
  st.pc.qword = addr;
  st.gpr.x2.qword = 0x0000'0000'0000'2001ULL;
  st.gpr.x5.qword = 0u;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_jalr_x5_x2_0", riscv::Bytes32(word), addr, &st, &mem);

  EXPECT_EQ(st.gpr.x5.qword, addr + 4);
  EXPECT_EQ(st.pc.qword, 0x2000u);
}

TEST(RISCV64, Branches_AllConditions_TakenAndNotTaken) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV64);

  struct Case {
    const char *name;
    uint32_t funct3;
    uint64_t rs1;
    uint64_t rs2;
    bool taken;
  };

  const std::vector<Case> cases = {
      {"beq_taken", /*funct3=*/0x0, /*rs1=*/0x11u, /*rs2=*/0x11u, /*taken=*/true},
      {"beq_not_taken", /*funct3=*/0x0, /*rs1=*/0x11u, /*rs2=*/0x22u, /*taken=*/false},

      {"bne_taken", /*funct3=*/0x1, /*rs1=*/0x11u, /*rs2=*/0x22u, /*taken=*/true},
      {"bne_not_taken", /*funct3=*/0x1, /*rs1=*/0x11u, /*rs2=*/0x11u, /*taken=*/false},

      // Signed comparisons.
      {"blt_taken", /*funct3=*/0x4, /*rs1=*/0xFFFF'FFFF'FFFF'FFFFULL, /*rs2=*/1u,
       /*taken=*/true},
      {"blt_not_taken", /*funct3=*/0x4, /*rs1=*/2u, /*rs2=*/1u,
       /*taken=*/false},

      {"bge_taken", /*funct3=*/0x5, /*rs1=*/2u, /*rs2=*/1u, /*taken=*/true},
      {"bge_not_taken", /*funct3=*/0x5, /*rs1=*/0xFFFF'FFFF'FFFF'FFFFULL, /*rs2=*/1u,
       /*taken=*/false},

      // Unsigned comparisons.
      {"bltu_taken", /*funct3=*/0x6, /*rs1=*/1u, /*rs2=*/0xFFFF'FFFF'FFFF'FFFFULL,
       /*taken=*/true},
      {"bltu_not_taken", /*funct3=*/0x6, /*rs1=*/0xFFFF'FFFF'FFFF'FFFFULL, /*rs2=*/1u,
       /*taken=*/false},

      {"bgeu_taken", /*funct3=*/0x7, /*rs1=*/0xFFFF'FFFF'FFFF'FFFFULL, /*rs2=*/1u,
       /*taken=*/true},
      {"bgeu_not_taken", /*funct3=*/0x7, /*rs1=*/1u, /*rs2=*/0xFFFF'FFFF'FFFF'FFFFULL,
       /*taken=*/false},
  };

  test_runner::MemoryHandler mem(llvm::endianness::little);

  for (const auto &tc : cases) {
    SCOPED_TRACE(tc.name);

    const uint64_t addr = 0x3000;
    const uint64_t target = addr + 8;

    // Generic form: b?? x1, x2, +8
    const auto word =
        riscv::EncodeB(riscv::kOpcodeBranch, tc.funct3, /*rs1=*/1, /*rs2=*/2,
                       /*imm13=*/8);

    RISCVState st = {};
    st.pc.qword = addr;
    st.gpr.x1.qword = tc.rs1;
    st.gpr.x2.qword = tc.rs2;

    riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
        lifter, tc.name, riscv::Bytes32(word), addr, &st, &mem);

    const uint64_t expected_pc = tc.taken ? target : (addr + 4);
    EXPECT_EQ(st.pc.qword, expected_pc);
  }
}

