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

#include "RISCVTestSpec.h"
#include "TestUtil.h"

TEST(RISCV32, Csrrw_Fcsr_WritesAndReturnsOld) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // csrrw x5, fcsr(0x003), x1
  const auto word =
      riscv::EncodeI(riscv::kOpcodeSystem, /*rd=*/5, /*funct3=*/0x1,
                     /*rs1=*/1, /*imm12=*/0x003);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"x1", uint32_t(0xABCDu)},
       {"fcsr", uint32_t(0x1234u)}},
      {{"x5", uint32_t(0x1234u)},
       {"fcsr", uint32_t(0xABCDu)},
       {"pc", uint32_t(0x1004u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, Fsflags_WritesLow5BitsAndReturnsOld) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fsflags x5, x1 (CSR=0x001)
  const auto word =
      riscv::EncodeI(riscv::kOpcodeSystem, /*rd=*/5, /*funct3=*/0x1,
                     /*rs1=*/1, /*imm12=*/0x001);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x2000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x2000u)},
       {"x1", uint32_t(0x2Au)},
       {"fflags", uint8_t(0x1Fu)}},
      {{"x5", uint32_t(0x1Fu)},
       {"fflags", uint8_t(0x0Au)},
       {"pc", uint32_t(0x2004u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, Csrrs_Fcsr_SetsBitsAndReturnsOld) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // csrrs x5, fcsr(0x003), x1
  const auto word =
      riscv::EncodeI(riscv::kOpcodeSystem, /*rd=*/5, /*funct3=*/0x2,
                     /*rs1=*/1, /*imm12=*/0x003);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"x1", uint32_t(0x00F0u)},
       {"fcsr", uint32_t(0x000Fu)}},
      {{"x5", uint32_t(0x000Fu)},
       {"fcsr", uint32_t(0x00FFu)},
       {"pc", uint32_t(0x1004u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, Csrrc_Fcsr_ClearsBitsAndReturnsOld) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // csrrc x5, fcsr(0x003), x1
  const auto word =
      riscv::EncodeI(riscv::kOpcodeSystem, /*rd=*/5, /*funct3=*/0x3,
                     /*rs1=*/1, /*imm12=*/0x003);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"x1", uint32_t(0x000Fu)},
       {"fcsr", uint32_t(0x00FFu)}},
      {{"x5", uint32_t(0x00FFu)},
       {"fcsr", uint32_t(0x00F0u)},
       {"pc", uint32_t(0x1004u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, Csrrwi_Fcsr_WritesImmAndReturnsOld) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // csrrwi x5, fcsr(0x003), 0x1A
  const auto word =
      riscv::EncodeI(riscv::kOpcodeSystem, /*rd=*/5, /*funct3=*/0x5,
                     /*rs1=*/0x1A, /*imm12=*/0x003);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"fcsr", uint32_t(0x00ABu)}},
      {{"x5", uint32_t(0x00ABu)},
       {"fcsr", uint32_t(0x001Au)},
       {"pc", uint32_t(0x1004u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, Csrrsi_Fcsr_SetsBitsWithImmAndReturnsOld) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // csrrsi x5, fcsr(0x003), 0x05
  const auto word =
      riscv::EncodeI(riscv::kOpcodeSystem, /*rd=*/5, /*funct3=*/0x6,
                     /*rs1=*/0x05, /*imm12=*/0x003);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"fcsr", uint32_t(0x00F0u)}},
      {{"x5", uint32_t(0x00F0u)},
       {"fcsr", uint32_t(0x00F5u)},
       {"pc", uint32_t(0x1004u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, Csrrci_Fcsr_ClearsBitsWithImmAndReturnsOld) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // csrrci x5, fcsr(0x003), 0x0F
  const auto word =
      riscv::EncodeI(riscv::kOpcodeSystem, /*rd=*/5, /*funct3=*/0x7,
                     /*rs1=*/0x0F, /*imm12=*/0x003);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"fcsr", uint32_t(0x00FFu)}},
      {{"x5", uint32_t(0x00FFu)},
       {"fcsr", uint32_t(0x00F0u)},
       {"pc", uint32_t(0x1004u)}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}
