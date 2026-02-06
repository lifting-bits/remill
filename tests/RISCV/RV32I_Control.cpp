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

TEST(RISCV32, Jalr_ClearsTargetLsbAndSetsLink) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  const uint64_t addr = 0x1000;

  // jalr x5, 0(x2)
  const auto word =
      riscv::EncodeI(riscv::kOpcodeJalr, /*rd=*/5, /*funct3=*/0, /*rs1=*/2,
                     /*imm12=*/0);

  RISCVState st = {};
  st.pc.dword = static_cast<uint32_t>(addr);
  st.gpr.x2.dword = 0x2001u;  // odd target; jalr must clear bit 0
  st.gpr.x5.dword = 0u;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_jalr_x5_x2_0", riscv::Bytes32(word), addr, &st, &mem);

  EXPECT_EQ(st.gpr.x5.dword, static_cast<uint32_t>(addr + 4));
  EXPECT_EQ(st.pc.dword, 0x2000u);
}

TEST(RISCV32, Branches_AllConditions_TakenAndNotTaken) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  struct Case {
    const char *name;
    uint32_t funct3;
    uint32_t rs1;
    uint32_t rs2;
    bool taken;
  };

  const std::vector<Case> cases = {
      {"beq_taken", /*funct3=*/0x0, /*rs1=*/0x11u, /*rs2=*/0x11u, /*taken=*/true},
      {"beq_not_taken", /*funct3=*/0x0, /*rs1=*/0x11u, /*rs2=*/0x22u, /*taken=*/false},

      {"bne_taken", /*funct3=*/0x1, /*rs1=*/0x11u, /*rs2=*/0x22u, /*taken=*/true},
      {"bne_not_taken", /*funct3=*/0x1, /*rs1=*/0x11u, /*rs2=*/0x11u, /*taken=*/false},

      // Signed comparisons.
      {"blt_taken", /*funct3=*/0x4, /*rs1=*/0xFFFF'FFFFu, /*rs2=*/1u,
       /*taken=*/true},
      {"blt_not_taken", /*funct3=*/0x4, /*rs1=*/2u, /*rs2=*/1u,
       /*taken=*/false},

      {"bge_taken", /*funct3=*/0x5, /*rs1=*/2u, /*rs2=*/1u, /*taken=*/true},
      {"bge_not_taken", /*funct3=*/0x5, /*rs1=*/0xFFFF'FFFFu, /*rs2=*/1u,
       /*taken=*/false},

      // Unsigned comparisons.
      {"bltu_taken", /*funct3=*/0x6, /*rs1=*/1u, /*rs2=*/0xFFFF'FFFFu,
       /*taken=*/true},
      {"bltu_not_taken", /*funct3=*/0x6, /*rs1=*/0xFFFF'FFFFu, /*rs2=*/1u,
       /*taken=*/false},

      {"bgeu_taken", /*funct3=*/0x7, /*rs1=*/0xFFFF'FFFFu, /*rs2=*/1u,
       /*taken=*/true},
      {"bgeu_not_taken", /*funct3=*/0x7, /*rs1=*/1u, /*rs2=*/0xFFFF'FFFFu,
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
    st.pc.dword = static_cast<uint32_t>(addr);
    st.gpr.x1.dword = tc.rs1;
    st.gpr.x2.dword = tc.rs2;

    riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
        lifter, tc.name, riscv::Bytes32(word), addr, &st, &mem);

    const uint32_t expected_pc =
        static_cast<uint32_t>(tc.taken ? target : (addr + 4));
    EXPECT_EQ(st.pc.dword, expected_pc);
  }
}

