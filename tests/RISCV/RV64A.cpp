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

// -- LR.D / SC.D --------------------------------------------------------------

TEST(RISCV64, LrD_LoadsAndSetsReservation) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t data_addr = 0x4000;
  const uint64_t val = 0x1122334455667788ULL;
  const auto lr = riscv::EncodeLrD(/*rd=*/3, /*rs1=*/1);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(lr),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0x1000)},
       {"x1", uint64_t(data_addr)}},
      {{"x3", uint64_t(val)},
       {"reserve_address", uint64_t(data_addr)},
       {"reserve", uint8_t(1u)},
       {"reserve_length", uint8_t(8u)},
       {"pc", uint64_t(0x1004)}},
      kRV64RegAccessors);
  spec.AddPrecWrite<uint64_t>(data_addr, val);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, ScD_SucceedsWithReservation) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t data_addr = 0x4000;
  const uint64_t old_val = 0x1122334455667788ULL;
  const uint64_t new_val = 0xAABBCCDDEEFF0011ULL;
  const auto sc = riscv::EncodeScD(/*rd=*/4, /*rs2=*/2, /*rs1=*/1);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1004, riscv::Bytes32(sc),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0x1004)},
       {"x1", uint64_t(data_addr)},
       {"x2", uint64_t(new_val)},
       {"reserve_address", uint64_t(data_addr)},
       {"reserve", uint8_t(1u)},
       {"reserve_length", uint8_t(8u)}},
      {{"x4", uint64_t(0u)},
       {"reserve_address", uint64_t(0u)},
       {"reserve", uint8_t(0u)},
       {"reserve_length", uint8_t(0u)},
       {"pc", uint64_t(0x1008)}},
      kRV64RegAccessors);
  spec.AddPrecWrite<uint64_t>(data_addr, old_val);
  spec.AddPostRead<uint64_t>(data_addr, new_val);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, ScD_FailsWithoutReservation) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t data_addr = 0x4000;
  const uint64_t old_val = 0x1122334455667788ULL;
  const uint64_t new_val = 0xAABBCCDDEEFF0011ULL;
  const auto sc = riscv::EncodeScD(/*rd=*/4, /*rs2=*/2, /*rs1=*/1);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x2000, riscv::Bytes32(sc),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0x2000)},
       {"x1", uint64_t(data_addr)},
       {"x2", uint64_t(new_val)},
       {"reserve", uint8_t(0u)}},
      {{"x4", uint64_t(1u)},
       {"pc", uint64_t(0x2004)}},
      kRV64RegAccessors);
  spec.AddPrecWrite<uint64_t>(data_addr, old_val);
  spec.AddPostRead<uint64_t>(data_addr, old_val);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, ScD_FailsWithAddressMismatch) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t reserved_addr = 0x4000;
  const uint64_t other_addr = 0x5000;
  const auto sc = riscv::EncodeScD(/*rd=*/4, /*rs2=*/2, /*rs1=*/1);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x3004, riscv::Bytes32(sc),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0x3004)},
       {"x1", uint64_t(other_addr)},
       {"x2", uint64_t(0xAABBCCDDEEFF0011ULL)},
       {"reserve_address", uint64_t(reserved_addr)},
       {"reserve", uint8_t(1u)},
       {"reserve_length", uint8_t(8u)}},
      {{"x4", uint64_t(1u)},
       {"reserve", uint8_t(1u)},
       {"reserve_address", uint64_t(reserved_addr)},
       {"reserve_length", uint8_t(8u)},
       {"pc", uint64_t(0x3008)}},
      kRV64RegAccessors);
  spec.AddPrecWrite<uint64_t>(other_addr, 0xDEADBEEFCAFEBABEull);
  spec.AddPostRead<uint64_t>(other_addr, 0xDEADBEEFCAFEBABEull);
  runner.RunTestSpec(spec);
}

// -- AMO.D --------------------------------------------------------------------

TEST(RISCV64, AmoswapD_ReturnsOldAndStoresNew) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t data_addr = 0x6000;
  const uint64_t old_val = 0x0102030405060708ULL;
  const uint64_t new_val = 0xA0B0C0D0E0F00011ULL;
  const auto enc = riscv::EncodeAmo(/*funct5=*/0x1U, /*aq=*/false,
                                    /*rl=*/false, /*rd=*/5,
                                    /*funct3=*/0x3U, /*rs1=*/1, /*rs2=*/2);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x2000, riscv::Bytes32(enc),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0x2000)},
       {"x1", uint64_t(data_addr)},
       {"x2", uint64_t(new_val)}},
      {{"x5", uint64_t(old_val)},
       {"pc", uint64_t(0x2004)}},
      kRV64RegAccessors);
  spec.AddPrecWrite<uint64_t>(data_addr, old_val);
  spec.AddPostRead<uint64_t>(data_addr, new_val);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, AmoaddD_ReturnsOldAndStoresSum) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t data_addr = 0x6000;
  const uint64_t old_val = 0x0000000000000010ULL;
  const uint64_t addend = 0x0000000000000020ULL;
  const auto enc = riscv::EncodeAmo(/*funct5=*/0x0U, /*aq=*/false,
                                    /*rl=*/false, /*rd=*/5,
                                    /*funct3=*/0x3U, /*rs1=*/1, /*rs2=*/2);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x2000, riscv::Bytes32(enc),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0x2000)},
       {"x1", uint64_t(data_addr)},
       {"x2", uint64_t(addend)}},
      {{"x5", uint64_t(old_val)},
       {"pc", uint64_t(0x2004)}},
      kRV64RegAccessors);
  spec.AddPrecWrite<uint64_t>(data_addr, old_val);
  spec.AddPostRead<uint64_t>(data_addr, old_val + addend);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, AmoxorD_ReturnsOldAndStoresXor) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t data_addr = 0x6000;
  const uint64_t old_val = 0xFF00FF00FF00FF00ULL;
  const uint64_t operand = 0x0F0F0F0F0F0F0F0FULL;
  const auto enc = riscv::EncodeAmo(/*funct5=*/0x4U, /*aq=*/false,
                                    /*rl=*/false, /*rd=*/5,
                                    /*funct3=*/0x3U, /*rs1=*/1, /*rs2=*/2);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x2000, riscv::Bytes32(enc),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0x2000)},
       {"x1", uint64_t(data_addr)},
       {"x2", uint64_t(operand)}},
      {{"x5", uint64_t(old_val)},
       {"pc", uint64_t(0x2004)}},
      kRV64RegAccessors);
  spec.AddPrecWrite<uint64_t>(data_addr, old_val);
  spec.AddPostRead<uint64_t>(data_addr, old_val ^ operand);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, AmoandD_ReturnsOldAndStoresAnd) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t data_addr = 0x6000;
  const uint64_t old_val = 0xFF00FF00FF00FF00ULL;
  const uint64_t operand = 0x0F0F0F0F0F0F0F0FULL;
  const auto enc = riscv::EncodeAmo(/*funct5=*/0xCU, /*aq=*/false,
                                    /*rl=*/false, /*rd=*/5,
                                    /*funct3=*/0x3U, /*rs1=*/1, /*rs2=*/2);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x2000, riscv::Bytes32(enc),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0x2000)},
       {"x1", uint64_t(data_addr)},
       {"x2", uint64_t(operand)}},
      {{"x5", uint64_t(old_val)},
       {"pc", uint64_t(0x2004)}},
      kRV64RegAccessors);
  spec.AddPrecWrite<uint64_t>(data_addr, old_val);
  spec.AddPostRead<uint64_t>(data_addr, old_val & operand);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, AmoorD_ReturnsOldAndStoresOr) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t data_addr = 0x6000;
  const uint64_t old_val = 0xFF00FF00FF00FF00ULL;
  const uint64_t operand = 0x0F0F0F0F0F0F0F0FULL;
  const auto enc = riscv::EncodeAmo(/*funct5=*/0x8U, /*aq=*/false,
                                    /*rl=*/false, /*rd=*/5,
                                    /*funct3=*/0x3U, /*rs1=*/1, /*rs2=*/2);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x2000, riscv::Bytes32(enc),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0x2000)},
       {"x1", uint64_t(data_addr)},
       {"x2", uint64_t(operand)}},
      {{"x5", uint64_t(old_val)},
       {"pc", uint64_t(0x2004)}},
      kRV64RegAccessors);
  spec.AddPrecWrite<uint64_t>(data_addr, old_val);
  spec.AddPostRead<uint64_t>(data_addr, old_val | operand);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, AmominD_ReturnsOldAndStoresSignedMin) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t data_addr = 0x6000;
  // 0xFFFFFFFFFFFFFFFE is -2 as signed, 0x0000000000000005 is 5; min is -2
  const uint64_t old_val = 0xFFFFFFFFFFFFFFFEULL;
  const uint64_t operand = 0x0000000000000005ULL;
  const auto enc = riscv::EncodeAmo(/*funct5=*/0x10U, /*aq=*/false,
                                    /*rl=*/false, /*rd=*/5,
                                    /*funct3=*/0x3U, /*rs1=*/1, /*rs2=*/2);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x2000, riscv::Bytes32(enc),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0x2000)},
       {"x1", uint64_t(data_addr)},
       {"x2", uint64_t(operand)}},
      {{"x5", uint64_t(old_val)},
       {"pc", uint64_t(0x2004)}},
      kRV64RegAccessors);
  spec.AddPrecWrite<uint64_t>(data_addr, old_val);
  spec.AddPostRead<uint64_t>(data_addr, 0xFFFFFFFFFFFFFFFEULL);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, AmomaxD_ReturnsOldAndStoresSignedMax) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t data_addr = 0x6000;
  // 0xFFFFFFFFFFFFFFFE is -2 as signed, 0x0000000000000005 is 5; max is 5
  const uint64_t old_val = 0xFFFFFFFFFFFFFFFEULL;
  const uint64_t operand = 0x0000000000000005ULL;
  const auto enc = riscv::EncodeAmo(/*funct5=*/0x14U, /*aq=*/false,
                                    /*rl=*/false, /*rd=*/5,
                                    /*funct3=*/0x3U, /*rs1=*/1, /*rs2=*/2);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x2000, riscv::Bytes32(enc),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0x2000)},
       {"x1", uint64_t(data_addr)},
       {"x2", uint64_t(operand)}},
      {{"x5", uint64_t(old_val)},
       {"pc", uint64_t(0x2004)}},
      kRV64RegAccessors);
  spec.AddPrecWrite<uint64_t>(data_addr, old_val);
  spec.AddPostRead<uint64_t>(data_addr, 0x0000000000000005ULL);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, AmominuD_ReturnsOldAndStoresUnsignedMin) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t data_addr = 0x6000;
  // Unsigned: 0xFFFFFFFFFFFFFFFE > 0x0000000000000005; min is 5
  const uint64_t old_val = 0xFFFFFFFFFFFFFFFEULL;
  const uint64_t operand = 0x0000000000000005ULL;
  const auto enc = riscv::EncodeAmo(/*funct5=*/0x18U, /*aq=*/false,
                                    /*rl=*/false, /*rd=*/5,
                                    /*funct3=*/0x3U, /*rs1=*/1, /*rs2=*/2);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x2000, riscv::Bytes32(enc),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0x2000)},
       {"x1", uint64_t(data_addr)},
       {"x2", uint64_t(operand)}},
      {{"x5", uint64_t(old_val)},
       {"pc", uint64_t(0x2004)}},
      kRV64RegAccessors);
  spec.AddPrecWrite<uint64_t>(data_addr, old_val);
  spec.AddPostRead<uint64_t>(data_addr, 0x0000000000000005ULL);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, AmomaxuD_ReturnsOldAndStoresUnsignedMax) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t data_addr = 0x6000;
  // Unsigned: 0xFFFFFFFFFFFFFFFE > 0x0000000000000005; max is 0xFFFFFFFFFFFFFFFE
  const uint64_t old_val = 0xFFFFFFFFFFFFFFFEULL;
  const uint64_t operand = 0x0000000000000005ULL;
  const auto enc = riscv::EncodeAmo(/*funct5=*/0x1CU, /*aq=*/false,
                                    /*rl=*/false, /*rd=*/5,
                                    /*funct3=*/0x3U, /*rs1=*/1, /*rs2=*/2);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x2000, riscv::Bytes32(enc),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0x2000)},
       {"x1", uint64_t(data_addr)},
       {"x2", uint64_t(operand)}},
      {{"x5", uint64_t(old_val)},
       {"pc", uint64_t(0x2004)}},
      kRV64RegAccessors);
  spec.AddPrecWrite<uint64_t>(data_addr, old_val);
  spec.AddPostRead<uint64_t>(data_addr, 0xFFFFFFFFFFFFFFFEULL);
  runner.RunTestSpec(spec);
}
