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

TEST(RISCV64, CompressedAddi_IncrementsPcBy2) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t addr = 0xD000;

  // c.addi x1, 1
  const auto half = riscv::EncodeCAddi(/*rd=*/1, /*imm6=*/1);

  test_runner::TestOutputSpec<RISCVState> spec(
      addr, riscv::Bytes16(half),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(addr)},
       {"x1", uint64_t(41)}},
      {{"pc", uint64_t(addr + 2)},
       {"x1", uint64_t(42)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedLw_SignExtendsToXlenAndSwStoresLow32Bits) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  const uint64_t base = 0x5000;

  // c.lw x9, 12(x8) => sign-extends 0x80000000 to 64 bits
  const auto clw = riscv::EncodeCLw(/*rd=*/9, /*rs1=*/8, /*uimm=*/12);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x1000, riscv::Bytes16(clw),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(0x1000)},
         {"x8", uint64_t(base)}},
        {{"pc", uint64_t(0x1002)},
         {"x9", uint64_t(0xFFFF'FFFF'8000'0000ULL)}},
        kRV64RegAccessors);
    spec.AddPrecWrite<uint32_t>(base + 12, 0x8000'0000u);
    runner.RunTestSpec(spec);
  }

  // c.sw x9, 16(x8) => stores low 32 bits
  const uint32_t store_val = 0xA0B0C0D0u;
  const auto csw = riscv::EncodeCSw(/*rs2=*/9, /*rs1=*/8, /*uimm=*/16);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x1002, riscv::Bytes16(csw),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint64_t(0x1002)},
         {"x8", uint64_t(base)},
         {"x9", uint64_t(store_val)}},
        {{"pc", uint64_t(0x1004)}},
        kRV64RegAccessors);
    spec.AddPostRead<uint32_t>(base + 16, store_val);
    runner.RunTestSpec(spec);
  }
}

TEST(RISCV64, CompressedJ_JumpsRelative) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.j +8
  const auto halfword = riscv::EncodeCJ(/*imm12=*/8);

  test_runner::TestOutputSpec<RISCVState> spec(
      0x2000, riscv::Bytes16(halfword),
      remill::Instruction::Category::kCategoryDirectJump,
      {{"pc", uint64_t(0x2000)}},
      {{"pc", uint64_t(0x2008)}},
      kRV64RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV64, CompressedBeqz_TakenAndNotTaken) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV64> runner(context);

  // c.beqz x8, +8
  const auto halfword = riscv::EncodeCBeqz(/*rs1=*/8, /*imm9=*/8);

  // Taken: x8 == 0
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x3000, riscv::Bytes16(halfword),
        remill::Instruction::Category::kCategoryConditionalBranch,
        {{"pc", uint64_t(0x3000)},
         {"x8", uint64_t(0)}},
        {{"pc", uint64_t(0x3008)}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }

  // Not taken: x8 != 0
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x3000, riscv::Bytes16(halfword),
        remill::Instruction::Category::kCategoryConditionalBranch,
        {{"pc", uint64_t(0x3000)},
         {"x8", uint64_t(1)}},
        {{"pc", uint64_t(0x3002)}},
        kRV64RegAccessors);
    runner.RunTestSpec(spec);
  }
}
