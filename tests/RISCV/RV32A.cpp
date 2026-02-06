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

TEST(RISCV32, LrScW_Success) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t data_addr = 0x4000;
  const uint32_t old_val = 0x11223344u;
  const uint32_t new_val = 0xAABBCCDDu;
  mem.WriteMemory<uint32_t>(data_addr, old_val);

  RISCVState st = {};
  st.pc.dword = 0x1000u;
  st.gpr.x1.dword = static_cast<uint32_t>(data_addr);
  st.gpr.x2.dword = new_val;

  // lr.w x3, (x1)
  const auto lr = riscv::EncodeLrW(/*rd=*/3, /*rs1=*/1);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_lr_w_x3_x1", riscv::Bytes32(lr), /*addr=*/0x1000, &st,
      &mem);

  EXPECT_EQ(st.gpr.x3.dword, old_val);
  EXPECT_EQ(st.reserve_address.dword, static_cast<uint32_t>(data_addr));
  EXPECT_EQ(st.reserve, 1u);
  EXPECT_EQ(st.reserve_length, 4u);
  EXPECT_EQ(st.pc.dword, 0x1004u);

  // sc.w x4, x2, (x1)
  const auto sc = riscv::EncodeScW(/*rd=*/4, /*rs2=*/2, /*rs1=*/1);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_sc_w_x4_x2_x1", riscv::Bytes32(sc), /*addr=*/0x1004,
      &st, &mem);

  EXPECT_EQ(st.gpr.x4.dword, 0u);
  EXPECT_EQ(mem.ReadMemory<uint32_t>(data_addr), new_val);
  EXPECT_EQ(st.reserve_address.dword, 0u);
  EXPECT_EQ(st.reserve, 0u);
  EXPECT_EQ(st.reserve_length, 0u);
  EXPECT_EQ(st.pc.dword, 0x1008u);
}

TEST(RISCV32, ScW_FailsWithoutReservation) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t data_addr = 0x4000;
  const uint32_t old_val = 0x11223344u;
  const uint32_t new_val = 0xAABBCCDDu;
  mem.WriteMemory<uint32_t>(data_addr, old_val);

  RISCVState st = {};
  st.pc.dword = 0x2000u;
  st.gpr.x1.dword = static_cast<uint32_t>(data_addr);
  st.gpr.x2.dword = new_val;

  // sc.w x4, x2, (x1)
  const auto sc = riscv::EncodeScW(/*rd=*/4, /*rs2=*/2, /*rs1=*/1);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_sc_w_fail_no_res", riscv::Bytes32(sc), /*addr=*/0x2000,
      &st, &mem);

  EXPECT_EQ(st.gpr.x4.dword, 1u);
  EXPECT_EQ(mem.ReadMemory<uint32_t>(data_addr), old_val);
  EXPECT_EQ(st.pc.dword, 0x2004u);
}

TEST(RISCV32, ScW_FailsWithAddressMismatch) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t reserved_addr = 0x4000;
  const uint64_t other_addr = 0x5000;
  mem.WriteMemory<uint32_t>(reserved_addr, 0x12345678u);
  mem.WriteMemory<uint32_t>(other_addr, 0xDEADBEEFu);

  RISCVState st = {};
  st.pc.dword = 0x3000u;
  st.gpr.x1.dword = static_cast<uint32_t>(reserved_addr);
  st.gpr.x2.dword = 0xAABBCCDDu;

  // lr.w x3, (x1)
  const auto lr = riscv::EncodeLrW(/*rd=*/3, /*rs1=*/1);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_lr_w_addr_mismatch", riscv::Bytes32(lr), /*addr=*/0x3000,
      &st, &mem);

  EXPECT_EQ(st.reserve, 1u);
  EXPECT_EQ(st.reserve_address.dword, static_cast<uint32_t>(reserved_addr));
  EXPECT_EQ(st.reserve_length, 4u);
  EXPECT_EQ(st.pc.dword, 0x3004u);

  // sc.w x4, x2, (x1) but with a different address in x1.
  st.gpr.x1.dword = static_cast<uint32_t>(other_addr);
  const auto sc = riscv::EncodeScW(/*rd=*/4, /*rs2=*/2, /*rs1=*/1);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_sc_w_addr_mismatch", riscv::Bytes32(sc), /*addr=*/0x3004,
      &st, &mem);

  EXPECT_EQ(st.gpr.x4.dword, 1u);
  EXPECT_EQ(mem.ReadMemory<uint32_t>(other_addr), 0xDEADBEEFu);

  // The spec keeps the reservation unchanged on failure.
  EXPECT_EQ(st.reserve, 1u);
  EXPECT_EQ(st.reserve_address.dword, static_cast<uint32_t>(reserved_addr));
  EXPECT_EQ(st.reserve_length, 4u);
  EXPECT_EQ(st.pc.dword, 0x3008u);
}

TEST(RISCV32, AmoswapW_ReturnsOldAndStoresNew) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::ArchName::kArchRISCV32);

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t data_addr = 0x6000;
  const uint32_t old_val = 0x01020304u;
  const uint32_t new_val = 0xA0B0C0D0u;
  mem.WriteMemory<uint32_t>(data_addr, old_val);

  RISCVState st = {};
  st.pc.dword = 0x4000u;
  st.gpr.x1.dword = static_cast<uint32_t>(data_addr);
  st.gpr.x2.dword = new_val;
  st.gpr.x5.dword = 0u;

  // amoswap.w x5, x2, (x1)
  const auto amoswap = riscv::EncodeAmo(/*funct5=*/0x1U, /*aq=*/false,
                                       /*rl=*/false, /*rd=*/5,
                                       /*funct3=*/0x2U, /*rs1=*/1, /*rs2=*/2);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_amoswap_w_x5_x2_x1", riscv::Bytes32(amoswap),
      /*addr=*/0x4000, &st, &mem);

  EXPECT_EQ(st.gpr.x5.dword, old_val);
  EXPECT_EQ(mem.ReadMemory<uint32_t>(data_addr), new_val);
  EXPECT_EQ(st.pc.dword, 0x4004u);
}

