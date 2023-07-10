/*
 * Copyright (c) 2019 Trail of Bits, Inc.
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

#include <glog/logging.h>
#include <remill/Arch/SPARC32/SPARC32Base.h>
#include <remill/Arch/ArchBase.h>  // For `Arch` and `ArchImpl`.

#include "Decode.h"
#include "remill/Arch/Instruction.h"
#include "remill/Arch/Name.h"
#include "remill/BC/ABI.h"
#include "remill/BC/Util.h"
#include "remill/OS/OS.h"

// clang-format off
#define INCLUDED_FROM_REMILL
#include "remill/Arch/SPARC32/Runtime/State.h"

// clang-format on

namespace remill {
namespace sparc {

const std::string_view kCCRName[4] = {"icc", {}, "xcc", {}};

const std::string_view kFCCRName[8] = {"fcc0", "fcc1", "fcc2", "fcc3",
                                       "icc",  {},     "xcc",  {}};

const std::string_view kReadIntRegName[32] = {
    "g0", "g1", "g2", "g3", "g4", "g5", "g6", "g7", "o0", "o1", "o2",
    "o3", "o4", "o5", "sp", "o7", "l0", "l1", "l2", "l3", "l4", "l5",
    "l6", "l7", "i0", "i1", "i2", "i3", "i4", "i5", "fp", "i7"};

const std::string_view kWriteIntRegName[32] = {"ignore_write_to_g0",
                                               "g1",
                                               "g2",
                                               "g3",
                                               "g4",
                                               "g5",
                                               "g6",
                                               "g7",
                                               "o0",
                                               "o1",
                                               "o2",
                                               "o3",
                                               "o4",
                                               "o5",
                                               "o6",
                                               "o7",
                                               "l0",
                                               "l1",
                                               "l2",
                                               "l3",
                                               "l4",
                                               "l5",
                                               "l6",
                                               "l7",
                                               "i0",
                                               "i1",
                                               "i2",
                                               "i3",
                                               "i4",
                                               "i5",
                                               "i6",
                                               "i7"};

const std::string_view kCondName[16] = {
    [0b0000] = "N",   [0b0001] = "E",  [0b0010] = "LE",  [0b0011] = "L",
    [0b0100] = "LEU", [0b0101] = "CS", [0b0110] = "NEG", [0b0111] = "VS",
    [0b1000] = "A",   [0b1001] = "NE", [0b1010] = "G",   [0b1011] = "GE",
    [0b1100] = "GU",  [0b1101] = "CC", [0b1110] = "POS", [0b1111] = "VC",
};

const std::string_view kFCondName[16] = {
    [0b0000] = "N",   [0b0001] = "NE", [0b0010] = "LG",  [0b0011] = "UL",
    [0b0100] = "L",   [0b0101] = "UG", [0b0110] = "G",   [0b0111] = "U",
    [0b1000] = "A",   [0b1001] = "E",  [0b1010] = "UE",  [0b1011] = "GE",
    [0b1100] = "UGE", [0b1101] = "LE", [0b1110] = "ULE", [0b1111] = "O"};

const std::string_view kRCondName[8] = {
    [0b000] = {}, [0b001] = "Z",  [0b010] = "LEZ", [0b011] = "LZ",
    [0b100] = {}, [0b101] = "NZ", [0b110] = "GZ",  [0b111] = "GEZ"};

void AddSrcRegop(Instruction &inst, const char *reg_name, unsigned size) {
  inst.operands.emplace_back();
  auto &op = inst.operands.back();
  op.type = Operand::kTypeRegister;
  op.size = size;
  op.action = Operand::kActionRead;
  op.reg.name = reg_name;
  op.reg.size = size;
}

void AddDestRegop(Instruction &inst, const char *reg_name, unsigned size) {
  inst.operands.emplace_back();
  auto &op = inst.operands.back();
  op.type = Operand::kTypeRegister;
  op.size = size;
  op.action = Operand::kActionWrite;
  op.reg.name = reg_name;
  op.reg.size = size;
}

void AddImmop(Instruction &inst, uint64_t imm, unsigned size, bool is_signed) {
  inst.operands.emplace_back();
  auto &op = inst.operands.back();
  op.type = Operand::kTypeImmediate;
  op.size = size;
  op.action = Operand::kActionRead;
  op.imm.val = imm;
  op.imm.is_signed = is_signed;
}


class SPARC32Arch final : public SPARC32ArchBase, public DefaultContextAndLifter {
 public:
  SPARC32Arch(llvm::LLVMContext *context_, OSName os_name_, ArchName arch_name_);

  virtual ~SPARC32Arch(void) = default;

  // Decode an instruction.
  bool ArchDecodeInstruction(uint64_t address, std::string_view instr_bytes,
                             Instruction &inst) const final;
};

SPARC32Arch::SPARC32Arch(llvm::LLVMContext *context_, OSName os_name_,
                         ArchName arch_name_)
    : ArchBase(context_, os_name_, arch_name_),
      SPARC32ArchBase(context_, os_name_, arch_name_),
      DefaultContextAndLifter(context_, os_name_, arch_name_) {}

// Decode an instruction.
bool SPARC32Arch::ArchDecodeInstruction(uint64_t address,
                                        std::string_view inst_bytes,
                                        Instruction &inst) const {
  inst.pc = address;
  inst.arch_name = arch_name;
  inst.sub_arch_name = arch_name;
  inst.branch_taken_arch_name = arch_name;
  inst.arch = this;
  inst.category = Instruction::kCategoryInvalid;
  inst.operands.clear();
  inst.next_pc = address + inst_bytes.size();  // Default fall-through.
  inst.branch_taken_pc = 0;
  inst.branch_not_taken_pc = 0;
  inst.has_branch_taken_delay_slot = false;
  inst.has_branch_not_taken_delay_slot = false;

  if (address % 4) {
    return false;
  }

  if (inst_bytes.size() != 4 && inst_bytes.size() != 8) {
    return false;
  }

  if (!inst.bytes.empty() && inst.bytes.data() == inst_bytes.data()) {
    inst.bytes.resize(inst_bytes.size());
  } else {
    inst.bytes = inst_bytes;
  }

  if (!sparc32::TryDecode(inst)) {
    inst.category = Instruction::kCategoryInvalid;
    inst.operands.clear();
    LOG(ERROR) << "Unable to decode: " << inst.Serialize();
    return false;
  }

  //  LOG(ERROR) << inst.Serialize();

  return inst.IsValid();
}

}  // namespace sparc

// TODO(pag): We pretend that these are singletons, but they aren't really!
Arch::ArchPtr Arch::GetSPARC32(llvm::LLVMContext *context_, OSName os_name_,
                             ArchName arch_name_) {
  if (arch_name_ == kArchSparc32) {
    return std::make_unique<sparc::SPARC32Arch>(context_, os_name_, arch_name_);

  } else {
    LOG(FATAL) << "Invalid arch name passed to Arch::GetSPARC32: "
               << GetArchName(arch_name_);
    return {};
  }
}

}  // namespace remill
