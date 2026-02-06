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

TEST(RISCV32, MulAndMulh_Basic) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  test_runner::MemoryHandler mem(llvm::endianness::little);

  const uint64_t addr = 0x1000;
  RISCVState st = {};
  st.pc.dword = static_cast<uint32_t>(addr);
  st.gpr.x1.dword = 7u;
  st.gpr.x2.dword = 9u;

  // mul x3, x1, x2
  const auto mul_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/3, /*funct3=*/0x0, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_mul_x3_x1_x2", riscv::Bytes32(mul_word), addr, &st,
      &mem);
  EXPECT_EQ(st.gpr.x3.dword, 63u);

  // mulh x4, x1, x2 with (-2147483648 * 2) => high 32 bits are 0xFFFF'FFFF
  const auto mulh_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/4, /*funct3=*/0x1, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  st.pc.dword = static_cast<uint32_t>(addr + 4);
  st.gpr.x1.dword = 0x8000'0000u;
  st.gpr.x2.dword = 2u;
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_mulh_x4_x1_x2", riscv::Bytes32(mulh_word), addr + 4,
      &st, &mem);
  EXPECT_EQ(st.gpr.x4.dword, 0xFFFF'FFFFu);
}

TEST(RISCV32, DivAndRem_Basic) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  test_runner::MemoryHandler mem(llvm::endianness::little);

  const uint64_t addr = 0x2000;
  RISCVState st = {};
  st.pc.dword = static_cast<uint32_t>(addr);
  st.gpr.x1.dword = static_cast<uint32_t>(-7);
  st.gpr.x2.dword = 2u;

  // div x3, x1, x2
  const auto div_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/3, /*funct3=*/0x4, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_div_x3_x1_x2", riscv::Bytes32(div_word), addr, &st,
      &mem);
  EXPECT_EQ(st.gpr.x3.dword, static_cast<uint32_t>(-3));

  // rem x4, x1, x2
  const auto rem_word =
      riscv::EncodeR(riscv::kOpcodeOp, /*rd=*/4, /*funct3=*/0x6, /*rs1=*/1,
                     /*rs2=*/2, /*funct7=*/0x01);
  st.pc.dword = static_cast<uint32_t>(addr + 4);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_rem_x4_x1_x2", riscv::Bytes32(rem_word), addr + 4, &st,
      &mem);
  EXPECT_EQ(st.gpr.x4.dword, static_cast<uint32_t>(-1));
}

