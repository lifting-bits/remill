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

TEST(RISCV32, Lui_SetsUpperImmediate) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  const uint64_t addr = 0x1000;

  // lui x1, 0x12345  => x1 = 0x12345000
  const auto word =
      riscv::EncodeU(riscv::kOpcodeLui, /*rd=*/1, /*imm20=*/0x12345);

  RISCVState st = {};
  st.pc.dword = static_cast<uint32_t>(addr);
  st.gpr.x1.dword = 0u;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_lui_x1_0x12345", riscv::Bytes32(word), addr, &st, &mem);

  EXPECT_EQ(st.gpr.x1.dword, 0x12345'000u);
  EXPECT_EQ(st.pc.dword, static_cast<uint32_t>(addr + 4));
}

TEST(RISCV32, Auipc_AddsPcRelativeUpperImmediate) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  const uint64_t addr = 0x2000;

  // auipc x1, 0x1 => x1 = pc + 0x1000
  const auto word =
      riscv::EncodeU(riscv::kOpcodeAuipc, /*rd=*/1, /*imm20=*/0x1);

  RISCVState st = {};
  st.pc.dword = static_cast<uint32_t>(addr);
  st.gpr.x1.dword = 0u;

  test_runner::MemoryHandler mem(llvm::endianness::little);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_auipc_x1_0x1", riscv::Bytes32(word), addr, &st, &mem);

  EXPECT_EQ(st.gpr.x1.dword, static_cast<uint32_t>(addr + 0x1000));
  EXPECT_EQ(st.pc.dword, static_cast<uint32_t>(addr + 4));
}

