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

TEST(RISCV32, LrScW_Success) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);
  auto &lifter = runner.GetLifter();

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
      lifter, "riscv32_lr_w_x3_x1", riscv::Bytes32(lr), 0x1000, &st, &mem);

  EXPECT_EQ(st.gpr.x3.dword, old_val);
  EXPECT_EQ(st.reserve_address.dword, static_cast<uint32_t>(data_addr));
  EXPECT_EQ(st.reserve, 1u);
  EXPECT_EQ(st.reserve_length, 4u);
  EXPECT_EQ(st.pc.dword, 0x1004u);

  // sc.w x4, x2, (x1)
  const auto sc = riscv::EncodeScW(/*rd=*/4, /*rs2=*/2, /*rs1=*/1);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_sc_w_x4_x2_x1", riscv::Bytes32(sc), 0x1004, &st, &mem);

  EXPECT_EQ(st.gpr.x4.dword, 0u);
  EXPECT_EQ(mem.ReadMemory<uint32_t>(data_addr), new_val);
  EXPECT_EQ(st.reserve_address.dword, 0u);
  EXPECT_EQ(st.reserve, 0u);
  EXPECT_EQ(st.reserve_length, 0u);
  EXPECT_EQ(st.pc.dword, 0x1008u);
}

TEST(RISCV32, ScW_FailsWithoutReservation) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);
  auto &lifter = runner.GetLifter();

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t data_addr = 0x4000;
  const uint32_t old_val = 0x11223344u;
  const uint32_t new_val = 0xAABBCCDDu;
  mem.WriteMemory<uint32_t>(data_addr, old_val);

  RISCVState st = {};
  st.pc.dword = 0x2000u;
  st.gpr.x1.dword = static_cast<uint32_t>(data_addr);
  st.gpr.x2.dword = new_val;

  // sc.w x4, x2, (x1) without prior lr.w
  const auto sc = riscv::EncodeScW(/*rd=*/4, /*rs2=*/2, /*rs1=*/1);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_sc_w_fail_no_res", riscv::Bytes32(sc), 0x2000, &st,
      &mem);

  EXPECT_EQ(st.gpr.x4.dword, 1u);
  EXPECT_EQ(mem.ReadMemory<uint32_t>(data_addr), old_val);
  EXPECT_EQ(st.pc.dword, 0x2004u);
}

TEST(RISCV32, ScW_FailsWithAddressMismatch) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);
  auto &lifter = runner.GetLifter();

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
      lifter, "riscv32_lr_w_addr_mismatch", riscv::Bytes32(lr), 0x3000, &st,
      &mem);

  EXPECT_EQ(st.reserve, 1u);
  EXPECT_EQ(st.reserve_address.dword, static_cast<uint32_t>(reserved_addr));
  EXPECT_EQ(st.reserve_length, 4u);
  EXPECT_EQ(st.pc.dword, 0x3004u);

  // sc.w x4, x2, (x1) but x1 now points to a different address
  st.gpr.x1.dword = static_cast<uint32_t>(other_addr);
  const auto sc = riscv::EncodeScW(/*rd=*/4, /*rs2=*/2, /*rs1=*/1);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_sc_w_addr_mismatch", riscv::Bytes32(sc), 0x3004, &st,
      &mem);

  EXPECT_EQ(st.gpr.x4.dword, 1u);
  EXPECT_EQ(mem.ReadMemory<uint32_t>(other_addr), 0xDEADBEEFu);
  EXPECT_EQ(st.reserve, 1u);
  EXPECT_EQ(st.reserve_address.dword, static_cast<uint32_t>(reserved_addr));
  EXPECT_EQ(st.reserve_length, 4u);
  EXPECT_EQ(st.pc.dword, 0x3008u);
}

TEST(RISCV32, AmoswapW_ReturnsOldAndStoresNew) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);
  auto &lifter = runner.GetLifter();

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
      lifter, "riscv32_amoswap_w_x5_x2_x1", riscv::Bytes32(amoswap), 0x4000,
      &st, &mem);

  EXPECT_EQ(st.gpr.x5.dword, old_val);
  EXPECT_EQ(mem.ReadMemory<uint32_t>(data_addr), new_val);
  EXPECT_EQ(st.pc.dword, 0x4004u);
}

TEST(RISCV32, AmoaddW_ReturnsOldAndStoresSum) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);
  auto &lifter = runner.GetLifter();

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t data_addr = 0x6000;
  const uint32_t old_val = 0x00000010u;
  const uint32_t addend = 0x00000020u;
  mem.WriteMemory<uint32_t>(data_addr, old_val);

  RISCVState st = {};
  st.pc.dword = 0x4000u;
  st.gpr.x1.dword = static_cast<uint32_t>(data_addr);
  st.gpr.x2.dword = addend;
  st.gpr.x5.dword = 0u;

  // amoadd.w x5, x2, (x1)
  const auto amoadd = riscv::EncodeAmo(/*funct5=*/0x0U, /*aq=*/false,
                                        /*rl=*/false, /*rd=*/5,
                                        /*funct3=*/0x2U, /*rs1=*/1, /*rs2=*/2);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_amoadd_w_x5_x2_x1", riscv::Bytes32(amoadd), 0x4000,
      &st, &mem);

  EXPECT_EQ(st.gpr.x5.dword, old_val);
  EXPECT_EQ(mem.ReadMemory<uint32_t>(data_addr), old_val + addend);
  EXPECT_EQ(st.pc.dword, 0x4004u);
}

TEST(RISCV32, AmoxorW_ReturnsOldAndStoresXor) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);
  auto &lifter = runner.GetLifter();

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t data_addr = 0x6000;
  const uint32_t old_val = 0xFF00FF00u;
  const uint32_t operand = 0x0F0F0F0Fu;
  mem.WriteMemory<uint32_t>(data_addr, old_val);

  RISCVState st = {};
  st.pc.dword = 0x4000u;
  st.gpr.x1.dword = static_cast<uint32_t>(data_addr);
  st.gpr.x2.dword = operand;
  st.gpr.x5.dword = 0u;

  // amoxor.w x5, x2, (x1)
  const auto amoxor = riscv::EncodeAmo(/*funct5=*/0x4U, /*aq=*/false,
                                        /*rl=*/false, /*rd=*/5,
                                        /*funct3=*/0x2U, /*rs1=*/1, /*rs2=*/2);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_amoxor_w_x5_x2_x1", riscv::Bytes32(amoxor), 0x4000,
      &st, &mem);

  EXPECT_EQ(st.gpr.x5.dword, old_val);
  EXPECT_EQ(mem.ReadMemory<uint32_t>(data_addr), old_val ^ operand);
  EXPECT_EQ(st.pc.dword, 0x4004u);
}

TEST(RISCV32, AmoandW_ReturnsOldAndStoresAnd) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);
  auto &lifter = runner.GetLifter();

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t data_addr = 0x6000;
  const uint32_t old_val = 0xFF00FF00u;
  const uint32_t operand = 0x0F0F0F0Fu;
  mem.WriteMemory<uint32_t>(data_addr, old_val);

  RISCVState st = {};
  st.pc.dword = 0x4000u;
  st.gpr.x1.dword = static_cast<uint32_t>(data_addr);
  st.gpr.x2.dword = operand;
  st.gpr.x5.dword = 0u;

  // amoand.w x5, x2, (x1)
  const auto amoand = riscv::EncodeAmo(/*funct5=*/0xCU, /*aq=*/false,
                                        /*rl=*/false, /*rd=*/5,
                                        /*funct3=*/0x2U, /*rs1=*/1, /*rs2=*/2);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_amoand_w_x5_x2_x1", riscv::Bytes32(amoand), 0x4000,
      &st, &mem);

  EXPECT_EQ(st.gpr.x5.dword, old_val);
  EXPECT_EQ(mem.ReadMemory<uint32_t>(data_addr), old_val & operand);
  EXPECT_EQ(st.pc.dword, 0x4004u);
}

TEST(RISCV32, AmoorW_ReturnsOldAndStoresOr) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);
  auto &lifter = runner.GetLifter();

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t data_addr = 0x6000;
  const uint32_t old_val = 0xFF00FF00u;
  const uint32_t operand = 0x0F0F0F0Fu;
  mem.WriteMemory<uint32_t>(data_addr, old_val);

  RISCVState st = {};
  st.pc.dword = 0x4000u;
  st.gpr.x1.dword = static_cast<uint32_t>(data_addr);
  st.gpr.x2.dword = operand;
  st.gpr.x5.dword = 0u;

  // amoor.w x5, x2, (x1)
  const auto amoor = riscv::EncodeAmo(/*funct5=*/0x8U, /*aq=*/false,
                                       /*rl=*/false, /*rd=*/5,
                                       /*funct3=*/0x2U, /*rs1=*/1, /*rs2=*/2);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_amoor_w_x5_x2_x1", riscv::Bytes32(amoor), 0x4000,
      &st, &mem);

  EXPECT_EQ(st.gpr.x5.dword, old_val);
  EXPECT_EQ(mem.ReadMemory<uint32_t>(data_addr), old_val | operand);
  EXPECT_EQ(st.pc.dword, 0x4004u);
}

TEST(RISCV32, AmominW_ReturnsOldAndStoresSignedMin) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);
  auto &lifter = runner.GetLifter();

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t data_addr = 0x6000;
  // 0xFFFFFFFE is -2 as signed, 0x00000005 is 5 as signed; min is -2
  const uint32_t old_val = 0xFFFFFFFEu;
  const uint32_t operand = 0x00000005u;
  mem.WriteMemory<uint32_t>(data_addr, old_val);

  RISCVState st = {};
  st.pc.dword = 0x4000u;
  st.gpr.x1.dword = static_cast<uint32_t>(data_addr);
  st.gpr.x2.dword = operand;
  st.gpr.x5.dword = 0u;

  // amomin.w x5, x2, (x1)
  const auto amomin = riscv::EncodeAmo(/*funct5=*/0x10U, /*aq=*/false,
                                        /*rl=*/false, /*rd=*/5,
                                        /*funct3=*/0x2U, /*rs1=*/1, /*rs2=*/2);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_amomin_w_x5_x2_x1", riscv::Bytes32(amomin), 0x4000,
      &st, &mem);

  EXPECT_EQ(st.gpr.x5.dword, old_val);
  // Signed min(-2, 5) = -2 = 0xFFFFFFFE
  EXPECT_EQ(mem.ReadMemory<uint32_t>(data_addr), 0xFFFFFFFEu);
  EXPECT_EQ(st.pc.dword, 0x4004u);
}

TEST(RISCV32, AmomaxW_ReturnsOldAndStoresSignedMax) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);
  auto &lifter = runner.GetLifter();

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t data_addr = 0x6000;
  // 0xFFFFFFFE is -2 as signed, 0x00000005 is 5 as signed; max is 5
  const uint32_t old_val = 0xFFFFFFFEu;
  const uint32_t operand = 0x00000005u;
  mem.WriteMemory<uint32_t>(data_addr, old_val);

  RISCVState st = {};
  st.pc.dword = 0x4000u;
  st.gpr.x1.dword = static_cast<uint32_t>(data_addr);
  st.gpr.x2.dword = operand;
  st.gpr.x5.dword = 0u;

  // amomax.w x5, x2, (x1)
  const auto amomax = riscv::EncodeAmo(/*funct5=*/0x14U, /*aq=*/false,
                                        /*rl=*/false, /*rd=*/5,
                                        /*funct3=*/0x2U, /*rs1=*/1, /*rs2=*/2);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_amomax_w_x5_x2_x1", riscv::Bytes32(amomax), 0x4000,
      &st, &mem);

  EXPECT_EQ(st.gpr.x5.dword, old_val);
  // Signed max(-2, 5) = 5
  EXPECT_EQ(mem.ReadMemory<uint32_t>(data_addr), 0x00000005u);
  EXPECT_EQ(st.pc.dword, 0x4004u);
}

TEST(RISCV32, AmominuW_ReturnsOldAndStoresUnsignedMin) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);
  auto &lifter = runner.GetLifter();

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t data_addr = 0x6000;
  // Unsigned: 0xFFFFFFFE > 0x00000005; unsigned min is 0x00000005
  const uint32_t old_val = 0xFFFFFFFEu;
  const uint32_t operand = 0x00000005u;
  mem.WriteMemory<uint32_t>(data_addr, old_val);

  RISCVState st = {};
  st.pc.dword = 0x4000u;
  st.gpr.x1.dword = static_cast<uint32_t>(data_addr);
  st.gpr.x2.dword = operand;
  st.gpr.x5.dword = 0u;

  // amominu.w x5, x2, (x1)
  const auto amominu = riscv::EncodeAmo(/*funct5=*/0x18U, /*aq=*/false,
                                         /*rl=*/false, /*rd=*/5,
                                         /*funct3=*/0x2U, /*rs1=*/1, /*rs2=*/2);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_amominu_w_x5_x2_x1", riscv::Bytes32(amominu), 0x4000,
      &st, &mem);

  EXPECT_EQ(st.gpr.x5.dword, old_val);
  // Unsigned min(0xFFFFFFFE, 0x00000005) = 0x00000005
  EXPECT_EQ(mem.ReadMemory<uint32_t>(data_addr), 0x00000005u);
  EXPECT_EQ(st.pc.dword, 0x4004u);
}

TEST(RISCV32, AmomaxuW_ReturnsOldAndStoresUnsignedMax) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);
  auto &lifter = runner.GetLifter();

  test_runner::MemoryHandler mem(llvm::endianness::little);
  const uint64_t data_addr = 0x6000;
  // Unsigned: 0xFFFFFFFE > 0x00000005; unsigned max is 0xFFFFFFFE
  const uint32_t old_val = 0xFFFFFFFEu;
  const uint32_t operand = 0x00000005u;
  mem.WriteMemory<uint32_t>(data_addr, old_val);

  RISCVState st = {};
  st.pc.dword = 0x4000u;
  st.gpr.x1.dword = static_cast<uint32_t>(data_addr);
  st.gpr.x2.dword = operand;
  st.gpr.x5.dword = 0u;

  // amomaxu.w x5, x2, (x1)
  const auto amomaxu = riscv::EncodeAmo(/*funct5=*/0x1CU, /*aq=*/false,
                                         /*rl=*/false, /*rd=*/5,
                                         /*funct3=*/0x2U, /*rs1=*/1, /*rs2=*/2);
  riscv::test::ExecuteOne<remill::ArchName::kArchRISCV32>(
      lifter, "riscv32_amomaxu_w_x5_x2_x1", riscv::Bytes32(amomaxu), 0x4000,
      &st, &mem);

  EXPECT_EQ(st.gpr.x5.dword, old_val);
  // Unsigned max(0xFFFFFFFE, 0x00000005) = 0xFFFFFFFE
  EXPECT_EQ(mem.ReadMemory<uint32_t>(data_addr), 0xFFFFFFFEu);
  EXPECT_EQ(st.pc.dword, 0x4004u);
}
