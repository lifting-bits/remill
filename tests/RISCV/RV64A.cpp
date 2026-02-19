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

#include <cstdint>

#include "RISCVTestSpec.h"
#include "TestUtil.h"

TEST(RISCV64, LrScD_Success) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);
  auto &lifter = runner.GetLifter();

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t data_addr = 0x4000;
  const uint64_t old_val = 0x1122334455667788ULL;
  const uint64_t new_val = 0xAABBCCDDEEFF0011ULL;
  mem.WriteMemory<uint64_t>(data_addr, old_val);

  RISCVState st = {};
  st.pc.qword = 0x1000;
  st.gpr.x1.qword = data_addr;
  st.gpr.x2.qword = new_val;

  // lr.d x3, (x1)
  const auto lr = riscv::EncodeLrD(/*rd=*/3, /*rs1=*/1);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_lr_d_x3_x1", riscv::Bytes32(lr), 0x1000, &st, &mem);

  EXPECT_EQ(st.gpr.x3.qword, old_val);
  EXPECT_EQ(st.reserve_address.qword, data_addr);
  EXPECT_EQ(st.reserve, 1u);
  EXPECT_EQ(st.reserve_length, 8u);
  EXPECT_EQ(st.pc.qword, 0x1004);

  // sc.d x4, x2, (x1)
  const auto sc = riscv::EncodeScD(/*rd=*/4, /*rs2=*/2, /*rs1=*/1);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_sc_d_x4_x2_x1", riscv::Bytes32(sc), 0x1004, &st, &mem);

  EXPECT_EQ(st.gpr.x4.qword, 0u);
  EXPECT_EQ(mem.ReadMemory<uint64_t>(data_addr), new_val);
  EXPECT_EQ(st.reserve_address.qword, 0u);
  EXPECT_EQ(st.reserve, 0u);
  EXPECT_EQ(st.reserve_length, 0u);
  EXPECT_EQ(st.pc.qword, 0x1008);
}

TEST(RISCV64, AmoswapD_ReturnsOldAndStoresNew) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);
  auto &lifter = runner.GetLifter();

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t data_addr = 0x6000;
  const uint64_t old_val = 0x0102030405060708ULL;
  const uint64_t new_val = 0xA0B0C0D0E0F00011ULL;
  mem.WriteMemory<uint64_t>(data_addr, old_val);

  RISCVState st = {};
  st.pc.qword = 0x2000;
  st.gpr.x1.qword = data_addr;
  st.gpr.x2.qword = new_val;
  st.gpr.x5.qword = 0u;

  // amoswap.d x5, x2, (x1)
  const auto amoswap = riscv::EncodeAmo(/*funct5=*/0x1U, /*aq=*/false,
                                         /*rl=*/false, /*rd=*/5,
                                         /*funct3=*/0x3U, /*rs1=*/1, /*rs2=*/2);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_amoswap_d_x5_x2_x1", riscv::Bytes32(amoswap), 0x2000,
      &st, &mem);

  EXPECT_EQ(st.gpr.x5.qword, old_val);
  EXPECT_EQ(mem.ReadMemory<uint64_t>(data_addr), new_val);
  EXPECT_EQ(st.pc.qword, 0x2004);
}
