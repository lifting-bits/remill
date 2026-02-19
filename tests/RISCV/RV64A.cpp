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

TEST(RISCV64, ScD_FailsWithoutReservation) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);
  auto &lifter = runner.GetLifter();

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t data_addr = 0x4000;
  const uint64_t old_val = 0x1122334455667788ULL;
  const uint64_t new_val = 0xAABBCCDDEEFF0011ULL;
  mem.WriteMemory<uint64_t>(data_addr, old_val);

  RISCVState st = {};
  st.pc.qword = 0x2000;
  st.gpr.x1.qword = data_addr;
  st.gpr.x2.qword = new_val;

  // sc.d x4, x2, (x1) without prior lr.d
  const auto sc = riscv::EncodeScD(/*rd=*/4, /*rs2=*/2, /*rs1=*/1);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_sc_d_fail_no_res", riscv::Bytes32(sc), 0x2000, &st,
      &mem);

  EXPECT_EQ(st.gpr.x4.qword, 1u);
  EXPECT_EQ(mem.ReadMemory<uint64_t>(data_addr), old_val);
  EXPECT_EQ(st.pc.qword, 0x2004);
}

TEST(RISCV64, ScD_FailsWithAddressMismatch) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);
  auto &lifter = runner.GetLifter();

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t reserved_addr = 0x4000;
  const uint64_t other_addr = 0x5000;
  mem.WriteMemory<uint64_t>(reserved_addr, 0x1234567890ABCDEFull);
  mem.WriteMemory<uint64_t>(other_addr, 0xDEADBEEFCAFEBABEull);

  RISCVState st = {};
  st.pc.qword = 0x3000;
  st.gpr.x1.qword = reserved_addr;
  st.gpr.x2.qword = 0xAABBCCDDEEFF0011ULL;

  // lr.d x3, (x1)
  const auto lr = riscv::EncodeLrD(/*rd=*/3, /*rs1=*/1);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_lr_d_addr_mismatch", riscv::Bytes32(lr), 0x3000, &st,
      &mem);

  EXPECT_EQ(st.reserve, 1u);
  EXPECT_EQ(st.reserve_address.qword, reserved_addr);
  EXPECT_EQ(st.reserve_length, 8u);
  EXPECT_EQ(st.pc.qword, 0x3004);

  // sc.d x4, x2, (x1) but x1 now points to a different address
  st.gpr.x1.qword = other_addr;
  const auto sc = riscv::EncodeScD(/*rd=*/4, /*rs2=*/2, /*rs1=*/1);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_sc_d_addr_mismatch", riscv::Bytes32(sc), 0x3004, &st,
      &mem);

  EXPECT_EQ(st.gpr.x4.qword, 1u);
  EXPECT_EQ(mem.ReadMemory<uint64_t>(other_addr), 0xDEADBEEFCAFEBABEull);
  EXPECT_EQ(st.reserve, 1u);
  EXPECT_EQ(st.reserve_address.qword, reserved_addr);
  EXPECT_EQ(st.reserve_length, 8u);
  EXPECT_EQ(st.pc.qword, 0x3008);
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

TEST(RISCV64, AmoaddD_ReturnsOldAndStoresSum) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);
  auto &lifter = runner.GetLifter();

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t data_addr = 0x6000;
  const uint64_t old_val = 0x0000000000000010ULL;
  const uint64_t addend = 0x0000000000000020ULL;
  mem.WriteMemory<uint64_t>(data_addr, old_val);

  RISCVState st = {};
  st.pc.qword = 0x2000;
  st.gpr.x1.qword = data_addr;
  st.gpr.x2.qword = addend;
  st.gpr.x5.qword = 0u;

  // amoadd.d x5, x2, (x1)
  const auto amoadd = riscv::EncodeAmo(/*funct5=*/0x0U, /*aq=*/false,
                                        /*rl=*/false, /*rd=*/5,
                                        /*funct3=*/0x3U, /*rs1=*/1, /*rs2=*/2);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_amoadd_d_x5_x2_x1", riscv::Bytes32(amoadd), 0x2000,
      &st, &mem);

  EXPECT_EQ(st.gpr.x5.qword, old_val);
  EXPECT_EQ(mem.ReadMemory<uint64_t>(data_addr), old_val + addend);
  EXPECT_EQ(st.pc.qword, 0x2004);
}

TEST(RISCV64, AmoxorD_ReturnsOldAndStoresXor) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);
  auto &lifter = runner.GetLifter();

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t data_addr = 0x6000;
  const uint64_t old_val = 0xFF00FF00FF00FF00ULL;
  const uint64_t operand = 0x0F0F0F0F0F0F0F0FULL;
  mem.WriteMemory<uint64_t>(data_addr, old_val);

  RISCVState st = {};
  st.pc.qword = 0x2000;
  st.gpr.x1.qword = data_addr;
  st.gpr.x2.qword = operand;
  st.gpr.x5.qword = 0u;

  // amoxor.d x5, x2, (x1)
  const auto amoxor = riscv::EncodeAmo(/*funct5=*/0x4U, /*aq=*/false,
                                        /*rl=*/false, /*rd=*/5,
                                        /*funct3=*/0x3U, /*rs1=*/1, /*rs2=*/2);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_amoxor_d_x5_x2_x1", riscv::Bytes32(amoxor), 0x2000,
      &st, &mem);

  EXPECT_EQ(st.gpr.x5.qword, old_val);
  EXPECT_EQ(mem.ReadMemory<uint64_t>(data_addr), old_val ^ operand);
  EXPECT_EQ(st.pc.qword, 0x2004);
}

TEST(RISCV64, AmoandD_ReturnsOldAndStoresAnd) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);
  auto &lifter = runner.GetLifter();

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t data_addr = 0x6000;
  const uint64_t old_val = 0xFF00FF00FF00FF00ULL;
  const uint64_t operand = 0x0F0F0F0F0F0F0F0FULL;
  mem.WriteMemory<uint64_t>(data_addr, old_val);

  RISCVState st = {};
  st.pc.qword = 0x2000;
  st.gpr.x1.qword = data_addr;
  st.gpr.x2.qword = operand;
  st.gpr.x5.qword = 0u;

  // amoand.d x5, x2, (x1)
  const auto amoand = riscv::EncodeAmo(/*funct5=*/0xCU, /*aq=*/false,
                                        /*rl=*/false, /*rd=*/5,
                                        /*funct3=*/0x3U, /*rs1=*/1, /*rs2=*/2);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_amoand_d_x5_x2_x1", riscv::Bytes32(amoand), 0x2000,
      &st, &mem);

  EXPECT_EQ(st.gpr.x5.qword, old_val);
  EXPECT_EQ(mem.ReadMemory<uint64_t>(data_addr), old_val & operand);
  EXPECT_EQ(st.pc.qword, 0x2004);
}

TEST(RISCV64, AmoorD_ReturnsOldAndStoresOr) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);
  auto &lifter = runner.GetLifter();

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t data_addr = 0x6000;
  const uint64_t old_val = 0xFF00FF00FF00FF00ULL;
  const uint64_t operand = 0x0F0F0F0F0F0F0F0FULL;
  mem.WriteMemory<uint64_t>(data_addr, old_val);

  RISCVState st = {};
  st.pc.qword = 0x2000;
  st.gpr.x1.qword = data_addr;
  st.gpr.x2.qword = operand;
  st.gpr.x5.qword = 0u;

  // amoor.d x5, x2, (x1)
  const auto amoor = riscv::EncodeAmo(/*funct5=*/0x8U, /*aq=*/false,
                                       /*rl=*/false, /*rd=*/5,
                                       /*funct3=*/0x3U, /*rs1=*/1, /*rs2=*/2);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_amoor_d_x5_x2_x1", riscv::Bytes32(amoor), 0x2000,
      &st, &mem);

  EXPECT_EQ(st.gpr.x5.qword, old_val);
  EXPECT_EQ(mem.ReadMemory<uint64_t>(data_addr), old_val | operand);
  EXPECT_EQ(st.pc.qword, 0x2004);
}

TEST(RISCV64, AmominD_ReturnsOldAndStoresSignedMin) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);
  auto &lifter = runner.GetLifter();

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t data_addr = 0x6000;
  // 0xFFFFFFFFFFFFFFFE is -2 as signed, 0x0000000000000005 is 5; min is -2
  const uint64_t old_val = 0xFFFFFFFFFFFFFFFEULL;
  const uint64_t operand = 0x0000000000000005ULL;
  mem.WriteMemory<uint64_t>(data_addr, old_val);

  RISCVState st = {};
  st.pc.qword = 0x2000;
  st.gpr.x1.qword = data_addr;
  st.gpr.x2.qword = operand;
  st.gpr.x5.qword = 0u;

  // amomin.d x5, x2, (x1)
  const auto amomin = riscv::EncodeAmo(/*funct5=*/0x10U, /*aq=*/false,
                                        /*rl=*/false, /*rd=*/5,
                                        /*funct3=*/0x3U, /*rs1=*/1, /*rs2=*/2);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_amomin_d_x5_x2_x1", riscv::Bytes32(amomin), 0x2000,
      &st, &mem);

  EXPECT_EQ(st.gpr.x5.qword, old_val);
  // Signed min(-2, 5) = -2 = 0xFFFFFFFFFFFFFFFE
  EXPECT_EQ(mem.ReadMemory<uint64_t>(data_addr), 0xFFFFFFFFFFFFFFFEULL);
  EXPECT_EQ(st.pc.qword, 0x2004);
}

TEST(RISCV64, AmomaxD_ReturnsOldAndStoresSignedMax) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);
  auto &lifter = runner.GetLifter();

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t data_addr = 0x6000;
  // 0xFFFFFFFFFFFFFFFE is -2 as signed, 0x0000000000000005 is 5; max is 5
  const uint64_t old_val = 0xFFFFFFFFFFFFFFFEULL;
  const uint64_t operand = 0x0000000000000005ULL;
  mem.WriteMemory<uint64_t>(data_addr, old_val);

  RISCVState st = {};
  st.pc.qword = 0x2000;
  st.gpr.x1.qword = data_addr;
  st.gpr.x2.qword = operand;
  st.gpr.x5.qword = 0u;

  // amomax.d x5, x2, (x1)
  const auto amomax = riscv::EncodeAmo(/*funct5=*/0x14U, /*aq=*/false,
                                        /*rl=*/false, /*rd=*/5,
                                        /*funct3=*/0x3U, /*rs1=*/1, /*rs2=*/2);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_amomax_d_x5_x2_x1", riscv::Bytes32(amomax), 0x2000,
      &st, &mem);

  EXPECT_EQ(st.gpr.x5.qword, old_val);
  // Signed max(-2, 5) = 5
  EXPECT_EQ(mem.ReadMemory<uint64_t>(data_addr), 0x0000000000000005ULL);
  EXPECT_EQ(st.pc.qword, 0x2004);
}

TEST(RISCV64, AmominuD_ReturnsOldAndStoresUnsignedMin) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);
  auto &lifter = runner.GetLifter();

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t data_addr = 0x6000;
  // Unsigned: 0xFFFFFFFFFFFFFFFE > 0x0000000000000005; min is 5
  const uint64_t old_val = 0xFFFFFFFFFFFFFFFEULL;
  const uint64_t operand = 0x0000000000000005ULL;
  mem.WriteMemory<uint64_t>(data_addr, old_val);

  RISCVState st = {};
  st.pc.qword = 0x2000;
  st.gpr.x1.qword = data_addr;
  st.gpr.x2.qword = operand;
  st.gpr.x5.qword = 0u;

  // amominu.d x5, x2, (x1)
  const auto amominu = riscv::EncodeAmo(/*funct5=*/0x18U, /*aq=*/false,
                                         /*rl=*/false, /*rd=*/5,
                                         /*funct3=*/0x3U, /*rs1=*/1, /*rs2=*/2);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_amominu_d_x5_x2_x1", riscv::Bytes32(amominu), 0x2000,
      &st, &mem);

  EXPECT_EQ(st.gpr.x5.qword, old_val);
  // Unsigned min(0xFFFFFFFFFFFFFFFE, 0x0000000000000005) = 0x0000000000000005
  EXPECT_EQ(mem.ReadMemory<uint64_t>(data_addr), 0x0000000000000005ULL);
  EXPECT_EQ(st.pc.qword, 0x2004);
}

TEST(RISCV64, AmomaxuD_ReturnsOldAndStoresUnsignedMax) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);
  auto &lifter = runner.GetLifter();

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t data_addr = 0x6000;
  // Unsigned: 0xFFFFFFFFFFFFFFFE > 0x0000000000000005; max is 0xFFFFFFFFFFFFFFFE
  const uint64_t old_val = 0xFFFFFFFFFFFFFFFEULL;
  const uint64_t operand = 0x0000000000000005ULL;
  mem.WriteMemory<uint64_t>(data_addr, old_val);

  RISCVState st = {};
  st.pc.qword = 0x2000;
  st.gpr.x1.qword = data_addr;
  st.gpr.x2.qword = operand;
  st.gpr.x5.qword = 0u;

  // amomaxu.d x5, x2, (x1)
  const auto amomaxu = riscv::EncodeAmo(/*funct5=*/0x1CU, /*aq=*/false,
                                         /*rl=*/false, /*rd=*/5,
                                         /*funct3=*/0x3U, /*rs1=*/1, /*rs2=*/2);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV64>(
      lifter, "riscv64_amomaxu_d_x5_x2_x1", riscv::Bytes32(amomaxu), 0x2000,
      &st, &mem);

  EXPECT_EQ(st.gpr.x5.qword, old_val);
  // Unsigned max(0xFFFFFFFFFFFFFFFE, 0x0000000000000005) = 0xFFFFFFFFFFFFFFFE
  EXPECT_EQ(mem.ReadMemory<uint64_t>(data_addr), 0xFFFFFFFFFFFFFFFEULL);
  EXPECT_EQ(st.pc.qword, 0x2004);
}
