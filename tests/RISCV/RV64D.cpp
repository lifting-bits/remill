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
#include <cstring>

#include "TestHarness.h"
#include "TestUtil.h"

namespace {

inline uint64_t BitsFromDouble(double value) {
  uint64_t bits = 0;
  static_assert(sizeof(bits) == sizeof(value));
  std::memcpy(&bits, &value, sizeof(bits));
  return bits;
}

inline double DoubleFromBits(uint64_t bits) {
  double value = 0.0;
  static_assert(sizeof(bits) == sizeof(value));
  std::memcpy(&value, &bits, sizeof(value));
  return value;
}

}  // namespace

TEST(RISCV64, FaddD_Basic) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV64);

  // fadd.d f3, f1, f2, rm=RNE(0)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3, /*funct3=*/0,
                                   /*rs1=*/1, /*rs2=*/2, /*funct7=*/0x1);

  RISCVState st = {};
  st.pc.qword = 0x1000;
  st.fpr.f1.qword = BitsFromDouble(1.5);
  st.fpr.f2.qword = BitsFromDouble(2.25);

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_fadd_d_f3_f1_f2", riscv::Bytes32(word), /*addr=*/0x1000,
      &st, &mem);

  EXPECT_EQ(DoubleFromBits(st.fpr.f3.qword), 1.5 + 2.25);
  EXPECT_EQ(st.pc.qword, 0x1004);
}

TEST(RISCV64, FldAndFsd_RoundTrip) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV64);

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t load_addr = 0x7000;
  const uint64_t store_addr = 0x8000;
  const uint64_t val_bits = BitsFromDouble(1.25);
  mem.WriteMemory<uint64_t>(load_addr, val_bits);

  RISCVState st = {};
  st.pc.qword = 0x2000;
  st.gpr.x10.qword = load_addr;
  st.gpr.x11.qword = store_addr;

  // fld f1, 0(x10)
  const auto fld =
      riscv::EncodeI(riscv::kOpcodeLoadFp, /*rd=*/1, /*funct3=*/0x3,
                     /*rs1=*/10, /*imm12=*/0);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_fld_f1_x10_0", riscv::Bytes32(fld), /*addr=*/0x2000, &st,
      &mem);

  EXPECT_EQ(st.fpr.f1.qword, val_bits);
  EXPECT_EQ(st.pc.qword, 0x2004);

  // fsd f1, 0(x11)
  const auto fsd =
      riscv::EncodeS(riscv::kOpcodeStoreFp, /*funct3=*/0x3, /*rs1=*/11,
                     /*rs2=*/1, /*imm12=*/0);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_fsd_f1_x11_0", riscv::Bytes32(fsd), /*addr=*/0x2004, &st,
      &mem);

  EXPECT_EQ(mem.ReadMemory<uint64_t>(store_addr), val_bits);
  EXPECT_EQ(st.pc.qword, 0x2008);
}

