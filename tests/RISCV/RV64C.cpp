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

TEST(RISCV64, CompressedLw_SignExtendsToXlenAndSwStoresLow32Bits) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV64);

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t base = 0x5000;
  const uint32_t load_val = 0x80000000u;
  const uint32_t store_val = 0xA0B0C0D0u;
  mem.WriteMemory<uint32_t>(base + 12u, load_val);
  mem.WriteMemory<uint32_t>(base + 16u, 0u);

  RISCVState st = {};
  st.pc.qword = 0x1000;
  st.gpr.x8.qword = base;

  // c.lw x9, 12(x8)
  const auto clw = riscv::EncodeCLw(/*rd=*/9, /*rs1=*/8, /*uimm=*/12);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_c_lw_x9_x8_12", riscv::Bytes16(clw), /*addr=*/0x1000,
      &st, &mem);

  EXPECT_EQ(st.gpr.x9.qword, 0xFFFF'FFFF'8000'0000ULL);
  EXPECT_EQ(st.pc.qword, 0x1002);

  st.gpr.x9.qword = static_cast<uint64_t>(store_val);

  // c.sw x9, 16(x8)
  const auto csw = riscv::EncodeCSw(/*rs2=*/9, /*rs1=*/8, /*uimm=*/16);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_c_sw_x9_x8_16", riscv::Bytes16(csw), /*addr=*/0x1002,
      &st, &mem);

  EXPECT_EQ(mem.ReadMemory<uint32_t>(base + 16u), store_val);
  EXPECT_EQ(st.pc.qword, 0x1004);
}

TEST(RISCV64, CompressedJ_JumpsRelative) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV64);

  // c.j +8
  const auto halfword = riscv::EncodeCJ(/*imm12=*/8);

  RISCVState st = {};
  st.pc.qword = 0x2000;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_c_j_8", riscv::Bytes16(halfword), /*addr=*/0x2000, &st,
      &mem);

  EXPECT_EQ(st.pc.qword, 0x2008);
}

TEST(RISCV64, CompressedBeqz_TakenAndNotTaken) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV64);

  // c.beqz x8, +8
  const auto halfword = riscv::EncodeCBeqz(/*rs1=*/8, /*imm9=*/8);

  test_runner::MemoryHandler mem(llvm::endianness::little);

  {
    RISCVState st = {};
    st.pc.qword = 0x3000;
    st.gpr.x8.qword = 0u;

    riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
        lifter, "riscv64_c_beqz_taken", riscv::Bytes16(halfword),
        /*addr=*/0x3000, &st, &mem);

    EXPECT_EQ(st.pc.qword, 0x3008);
  }

  {
    RISCVState st = {};
    st.pc.qword = 0x3000;
    st.gpr.x8.qword = 1u;

    riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
        lifter, "riscv64_c_beqz_not_taken", riscv::Bytes16(halfword),
        /*addr=*/0x3000, &st, &mem);

    EXPECT_EQ(st.pc.qword, 0x3002);
  }
}

