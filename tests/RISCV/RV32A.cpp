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
#include <remill/Arch/Instruction.h>
#include <remill/Arch/Name.h>

#include <cstdint>

#include "RISCVTestSpec.h"
#include "TestUtil.h"

// -- LR.W / SC.W --------------------------------------------------------------

TEST(RISCV32, LrW_LoadsAndSetsReservation) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t data_addr = 0x4000;
  const uint32_t val = 0x11223344u;
  const auto lr = riscv::EncodeLrW(/*rd=*/3, /*rs1=*/1);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(lr),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"x1", uint32_t(data_addr)}},
      {{"x3", uint32_t(val)},
       {"reserve_address", uint32_t(data_addr)},
       {"reserve", uint8_t(1u)},
       {"reserve_length", uint8_t(4u)},
       {"pc", uint32_t(0x1004u)}},
      kRV32RegAccessors);
  spec.AddPrecWrite<uint32_t>(data_addr, val);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, ScW_SucceedsWithReservation) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t data_addr = 0x4000;
  const uint32_t old_val = 0x11223344u;
  const uint32_t new_val = 0xAABBCCDDu;
  const auto sc = riscv::EncodeScW(/*rd=*/4, /*rs2=*/2, /*rs1=*/1);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1004, riscv::Bytes32(sc),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1004u)},
       {"x1", uint32_t(data_addr)},
       {"x2", uint32_t(new_val)},
       {"reserve_address", uint32_t(data_addr)},
       {"reserve", uint8_t(1u)},
       {"reserve_length", uint8_t(4u)}},
      {{"x4", uint32_t(0u)},
       {"reserve_address", uint32_t(0u)},
       {"reserve", uint8_t(0u)},
       {"reserve_length", uint8_t(0u)},
       {"pc", uint32_t(0x1008u)}},
      kRV32RegAccessors);
  spec.AddPrecWrite<uint32_t>(data_addr, old_val);
  spec.AddPostRead<uint32_t>(data_addr, new_val);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, ScW_FailsWithoutReservation) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t data_addr = 0x4000;
  const uint32_t old_val = 0x11223344u;
  const uint32_t new_val = 0xAABBCCDDu;
  const auto sc = riscv::EncodeScW(/*rd=*/4, /*rs2=*/2, /*rs1=*/1);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x2000, riscv::Bytes32(sc),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x2000u)},
       {"x1", uint32_t(data_addr)},
       {"x2", uint32_t(new_val)},
       {"reserve", uint8_t(0u)}},
      {{"x4", uint32_t(1u)},
       {"pc", uint32_t(0x2004u)}},
      kRV32RegAccessors);
  spec.AddPrecWrite<uint32_t>(data_addr, old_val);
  spec.AddPostRead<uint32_t>(data_addr, old_val);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, ScW_FailsWithAddressMismatch) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t reserved_addr = 0x4000;
  const uint64_t other_addr = 0x5000;
  const auto sc = riscv::EncodeScW(/*rd=*/4, /*rs2=*/2, /*rs1=*/1);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x3004, riscv::Bytes32(sc),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x3004u)},
       {"x1", uint32_t(other_addr)},
       {"x2", uint32_t(0xAABBCCDDu)},
       {"reserve_address", uint32_t(reserved_addr)},
       {"reserve", uint8_t(1u)},
       {"reserve_length", uint8_t(4u)}},
      {{"x4", uint32_t(1u)},
       {"reserve", uint8_t(1u)},
       {"reserve_address", uint32_t(reserved_addr)},
       {"reserve_length", uint8_t(4u)},
       {"pc", uint32_t(0x3008u)}},
      kRV32RegAccessors);
  spec.AddPrecWrite<uint32_t>(other_addr, 0xDEADBEEFu);
  spec.AddPostRead<uint32_t>(other_addr, 0xDEADBEEFu);
  runner.RunTestSpec(spec);
}

// -- AMO.W --------------------------------------------------------------------

TEST(RISCV32, AmoswapW_ReturnsOldAndStoresNew) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t data_addr = 0x6000;
  const uint32_t old_val = 0x01020304u;
  const uint32_t new_val = 0xA0B0C0D0u;
  const auto enc = riscv::EncodeAmo(/*funct5=*/0x1U, /*aq=*/false,
                                    /*rl=*/false, /*rd=*/5,
                                    /*funct3=*/0x2U, /*rs1=*/1, /*rs2=*/2);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x4000, riscv::Bytes32(enc),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x4000u)},
       {"x1", uint32_t(data_addr)},
       {"x2", uint32_t(new_val)}},
      {{"x5", uint32_t(old_val)},
       {"pc", uint32_t(0x4004u)}},
      kRV32RegAccessors);
  spec.AddPrecWrite<uint32_t>(data_addr, old_val);
  spec.AddPostRead<uint32_t>(data_addr, new_val);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, AmoaddW_ReturnsOldAndStoresSum) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t data_addr = 0x6000;
  const uint32_t old_val = 0x00000010u;
  const uint32_t addend = 0x00000020u;
  const auto enc = riscv::EncodeAmo(/*funct5=*/0x0U, /*aq=*/false,
                                    /*rl=*/false, /*rd=*/5,
                                    /*funct3=*/0x2U, /*rs1=*/1, /*rs2=*/2);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x4000, riscv::Bytes32(enc),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x4000u)},
       {"x1", uint32_t(data_addr)},
       {"x2", uint32_t(addend)}},
      {{"x5", uint32_t(old_val)},
       {"pc", uint32_t(0x4004u)}},
      kRV32RegAccessors);
  spec.AddPrecWrite<uint32_t>(data_addr, old_val);
  spec.AddPostRead<uint32_t>(data_addr, old_val + addend);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, AmoxorW_ReturnsOldAndStoresXor) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t data_addr = 0x6000;
  const uint32_t old_val = 0xFF00FF00u;
  const uint32_t operand = 0x0F0F0F0Fu;
  const auto enc = riscv::EncodeAmo(/*funct5=*/0x4U, /*aq=*/false,
                                    /*rl=*/false, /*rd=*/5,
                                    /*funct3=*/0x2U, /*rs1=*/1, /*rs2=*/2);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x4000, riscv::Bytes32(enc),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x4000u)},
       {"x1", uint32_t(data_addr)},
       {"x2", uint32_t(operand)}},
      {{"x5", uint32_t(old_val)},
       {"pc", uint32_t(0x4004u)}},
      kRV32RegAccessors);
  spec.AddPrecWrite<uint32_t>(data_addr, old_val);
  spec.AddPostRead<uint32_t>(data_addr, old_val ^ operand);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, AmoandW_ReturnsOldAndStoresAnd) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t data_addr = 0x6000;
  const uint32_t old_val = 0xFF00FF00u;
  const uint32_t operand = 0x0F0F0F0Fu;
  const auto enc = riscv::EncodeAmo(/*funct5=*/0xCU, /*aq=*/false,
                                    /*rl=*/false, /*rd=*/5,
                                    /*funct3=*/0x2U, /*rs1=*/1, /*rs2=*/2);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x4000, riscv::Bytes32(enc),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x4000u)},
       {"x1", uint32_t(data_addr)},
       {"x2", uint32_t(operand)}},
      {{"x5", uint32_t(old_val)},
       {"pc", uint32_t(0x4004u)}},
      kRV32RegAccessors);
  spec.AddPrecWrite<uint32_t>(data_addr, old_val);
  spec.AddPostRead<uint32_t>(data_addr, old_val & operand);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, AmoorW_ReturnsOldAndStoresOr) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t data_addr = 0x6000;
  const uint32_t old_val = 0xFF00FF00u;
  const uint32_t operand = 0x0F0F0F0Fu;
  const auto enc = riscv::EncodeAmo(/*funct5=*/0x8U, /*aq=*/false,
                                    /*rl=*/false, /*rd=*/5,
                                    /*funct3=*/0x2U, /*rs1=*/1, /*rs2=*/2);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x4000, riscv::Bytes32(enc),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x4000u)},
       {"x1", uint32_t(data_addr)},
       {"x2", uint32_t(operand)}},
      {{"x5", uint32_t(old_val)},
       {"pc", uint32_t(0x4004u)}},
      kRV32RegAccessors);
  spec.AddPrecWrite<uint32_t>(data_addr, old_val);
  spec.AddPostRead<uint32_t>(data_addr, old_val | operand);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, AmominW_ReturnsOldAndStoresSignedMin) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t data_addr = 0x6000;
  // 0xFFFFFFFE is -2 as signed, 0x00000005 is 5 as signed; min is -2
  const uint32_t old_val = 0xFFFFFFFEu;
  const uint32_t operand = 0x00000005u;
  const auto enc = riscv::EncodeAmo(/*funct5=*/0x10U, /*aq=*/false,
                                    /*rl=*/false, /*rd=*/5,
                                    /*funct3=*/0x2U, /*rs1=*/1, /*rs2=*/2);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x4000, riscv::Bytes32(enc),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x4000u)},
       {"x1", uint32_t(data_addr)},
       {"x2", uint32_t(operand)}},
      {{"x5", uint32_t(old_val)},
       {"pc", uint32_t(0x4004u)}},
      kRV32RegAccessors);
  spec.AddPrecWrite<uint32_t>(data_addr, old_val);
  spec.AddPostRead<uint32_t>(data_addr, 0xFFFFFFFEu);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, AmomaxW_ReturnsOldAndStoresSignedMax) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t data_addr = 0x6000;
  // 0xFFFFFFFE is -2 as signed, 0x00000005 is 5 as signed; max is 5
  const uint32_t old_val = 0xFFFFFFFEu;
  const uint32_t operand = 0x00000005u;
  const auto enc = riscv::EncodeAmo(/*funct5=*/0x14U, /*aq=*/false,
                                    /*rl=*/false, /*rd=*/5,
                                    /*funct3=*/0x2U, /*rs1=*/1, /*rs2=*/2);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x4000, riscv::Bytes32(enc),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x4000u)},
       {"x1", uint32_t(data_addr)},
       {"x2", uint32_t(operand)}},
      {{"x5", uint32_t(old_val)},
       {"pc", uint32_t(0x4004u)}},
      kRV32RegAccessors);
  spec.AddPrecWrite<uint32_t>(data_addr, old_val);
  spec.AddPostRead<uint32_t>(data_addr, 0x00000005u);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, AmominuW_ReturnsOldAndStoresUnsignedMin) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t data_addr = 0x6000;
  // Unsigned: 0xFFFFFFFE > 0x00000005; unsigned min is 0x00000005
  const uint32_t old_val = 0xFFFFFFFEu;
  const uint32_t operand = 0x00000005u;
  const auto enc = riscv::EncodeAmo(/*funct5=*/0x18U, /*aq=*/false,
                                    /*rl=*/false, /*rd=*/5,
                                    /*funct3=*/0x2U, /*rs1=*/1, /*rs2=*/2);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x4000, riscv::Bytes32(enc),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x4000u)},
       {"x1", uint32_t(data_addr)},
       {"x2", uint32_t(operand)}},
      {{"x5", uint32_t(old_val)},
       {"pc", uint32_t(0x4004u)}},
      kRV32RegAccessors);
  spec.AddPrecWrite<uint32_t>(data_addr, old_val);
  spec.AddPostRead<uint32_t>(data_addr, 0x00000005u);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, AmomaxuW_ReturnsOldAndStoresUnsignedMax) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t data_addr = 0x6000;
  // Unsigned: 0xFFFFFFFE > 0x00000005; unsigned max is 0xFFFFFFFE
  const uint32_t old_val = 0xFFFFFFFEu;
  const uint32_t operand = 0x00000005u;
  const auto enc = riscv::EncodeAmo(/*funct5=*/0x1CU, /*aq=*/false,
                                    /*rl=*/false, /*rd=*/5,
                                    /*funct3=*/0x2U, /*rs1=*/1, /*rs2=*/2);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x4000, riscv::Bytes32(enc),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x4000u)},
       {"x1", uint32_t(data_addr)},
       {"x2", uint32_t(operand)}},
      {{"x5", uint32_t(old_val)},
       {"pc", uint32_t(0x4004u)}},
      kRV32RegAccessors);
  spec.AddPrecWrite<uint32_t>(data_addr, old_val);
  spec.AddPostRead<uint32_t>(data_addr, 0xFFFFFFFEu);
  runner.RunTestSpec(spec);
}
