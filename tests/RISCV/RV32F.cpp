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
#include <cstring>

#include "RISCVTestSpec.h"
#include "TestUtil.h"

namespace {

inline uint32_t BitsFromFloat(float value) {
  uint32_t bits = 0;
  static_assert(sizeof(bits) == sizeof(value));
  std::memcpy(&bits, &value, sizeof(bits));
  return bits;
}

}  // namespace

TEST(RISCV32, FaddS_WritesLow32BitsAndZeroExtends) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  // fadd.s f3, f1, f2, rm=RNE(0)
  const auto word = riscv::EncodeR(riscv::kOpcodeOpFp, /*rd=*/3, /*funct3=*/0,
                                   /*rs1=*/1, /*rs2=*/2, /*funct7=*/0x0);

  // FPR accessors return qword for both RV32 and RV64
  test_runner::TestOutputSpec<RISCVState> spec(
      0x1000, riscv::Bytes32(word),
      remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint32_t(0x1000u)},
       {"f1", uint64_t(BitsFromFloat(1.5f))},
       {"f2", uint64_t(BitsFromFloat(2.25f))}},
      {{"pc", uint32_t(0x1004u)},
       {"f3", uint64_t(BitsFromFloat(1.5f + 2.25f))}},
      kRV32RegAccessors);
  runner.RunTestSpec(spec);
}

TEST(RISCV32, FlwAndFsw_RoundTrip) {
  llvm::LLVMContext context;
  RISCVTestSpecRunner<remill::ArchName::kArchRISCV32> runner(context);

  const uint64_t load_addr = 0x5000;
  const uint64_t store_addr = 0x6000;
  const uint32_t val_bits = BitsFromFloat(1.25f);

  // flw f1, 0(x10)
  const auto flw =
      riscv::EncodeI(riscv::kOpcodeLoadFp, /*rd=*/1, /*funct3=*/0x2,
                     /*rs1=*/10, /*imm12=*/0);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x2000, riscv::Bytes32(flw),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(0x2000u)},
         {"x10", uint32_t(load_addr)}},
        {{"pc", uint32_t(0x2004u)},
         {"f1", uint64_t(val_bits)}},
        kRV32RegAccessors);
    spec.AddPrecWrite<uint32_t>(load_addr, val_bits);
    runner.RunTestSpec(spec);
  }

  // fsw f1, 0(x11)
  const auto fsw =
      riscv::EncodeS(riscv::kOpcodeStoreFp, /*funct3=*/0x2, /*rs1=*/11,
                     /*rs2=*/1, /*imm12=*/0);
  {
    test_runner::TestOutputSpec<RISCVState> spec(
        0x2004, riscv::Bytes32(fsw),
        remill::Instruction::Category::kCategoryNormal,
        {{"pc", uint32_t(0x2004u)},
         {"x11", uint32_t(store_addr)},
         {"f1", uint64_t(val_bits)}},
        {{"pc", uint32_t(0x2008u)}},
        kRV32RegAccessors);
    spec.AddPostRead<uint32_t>(store_addr, val_bits);
    runner.RunTestSpec(spec);
  }
}
