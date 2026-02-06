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

TEST(RISCV32, CompressedLwAndSw_Use2ByteInstructions) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t base = 0x5000;
  const uint32_t load_val = 0xDEADBEEFu;
  const uint32_t store_val = 0xA0B0C0D0u;
  mem.WriteMemory<uint32_t>(base + 12u, load_val);
  mem.WriteMemory<uint32_t>(base + 16u, 0u);

  RISCVState st = {};
  st.pc.dword = 0x1000u;
  st.gpr.x8.dword = static_cast<uint32_t>(base);

  // c.lw x9, 12(x8)
  const auto clw = riscv::EncodeCLw(/*rd=*/9, /*rs1=*/8, /*uimm=*/12);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_c_lw_x9_x8_12", riscv::Bytes16(clw), /*addr=*/0x1000,
      &st, &mem);

  EXPECT_EQ(st.gpr.x9.dword, load_val);
  EXPECT_EQ(st.pc.dword, 0x1002u);

  st.gpr.x9.dword = store_val;

  // c.sw x9, 16(x8)
  const auto csw = riscv::EncodeCSw(/*rs2=*/9, /*rs1=*/8, /*uimm=*/16);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_c_sw_x9_x8_16", riscv::Bytes16(csw), /*addr=*/0x1002,
      &st, &mem);

  EXPECT_EQ(mem.ReadMemory<uint32_t>(base + 16u), store_val);
  EXPECT_EQ(st.pc.dword, 0x1004u);
}

TEST(RISCV32, CompressedJ_JumpsRelative) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  // c.j +8
  const auto halfword = riscv::EncodeCJ(/*imm12=*/8);

  RISCVState st = {};
  st.pc.dword = 0x2000u;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_c_j_8", riscv::Bytes16(halfword), /*addr=*/0x2000, &st,
      &mem);

  EXPECT_EQ(st.pc.dword, 0x2008u);
}

TEST(RISCV32, CompressedBeqz_TakenAndNotTaken) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  // c.beqz x8, +8
  const auto halfword = riscv::EncodeCBeqz(/*rs1=*/8, /*imm9=*/8);

  test_runner::MemoryHandler mem(llvm::endianness::little);

  {
    RISCVState st = {};
    st.pc.dword = 0x3000u;
    st.gpr.x8.dword = 0u;

    riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
        lifter, "riscv32_c_beqz_taken", riscv::Bytes16(halfword), /*addr=*/0x3000,
        &st, &mem);

    EXPECT_EQ(st.pc.dword, 0x3008u);
  }

  {
    RISCVState st = {};
    st.pc.dword = 0x3000u;
    st.gpr.x8.dword = 1u;

    riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
        lifter, "riscv32_c_beqz_not_taken", riscv::Bytes16(halfword),
        /*addr=*/0x3000, &st, &mem);

    EXPECT_EQ(st.pc.dword, 0x3002u);
  }
}

