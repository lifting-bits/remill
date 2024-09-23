/*
 * Copyright (c) 2020 Trail of Bits, Inc.
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

#include "AArch32Arch.h"

#include <glog/logging.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <remill/Arch/AArch32/ArchContext.h>

#include <iomanip>
#include <map>
#include <memory>
#include <sstream>
#include <string>

#include "remill/Arch/Instruction.h"
#include "remill/Arch/Name.h"
#include "remill/BC/ABI.h"
#include "remill/BC/Util.h"
#include "remill/BC/Version.h"
#include "remill/OS/OS.h"
// clang-format off
#define ADDRESS_SIZE 32
#include "remill/Arch/AArch32/Runtime/State.h"

// clang-format on

#include <remill/Arch/ArchBase.h>  // For `ArchImpl`.

namespace remill {

AArch32Arch::AArch32Arch(llvm::LLVMContext *context_, OSName os_name_,
                         ArchName arch_name_)
    : ArchBase(context_, os_name_, arch_name_),
      AArch32ArchBase(context_, os_name_, arch_name_),
      thumb_decoder(*this) {}

AArch32Arch::~AArch32Arch(void) {}

OperandLifter::OpLifterPtr AArch32Arch::DefaultLifter(
    const remill::IntrinsicTable &intrinsics_table) const {
  return std::make_shared<InstructionLifter>(this, intrinsics_table);
}

bool AArch32Arch::DecodeInstruction(uint64_t address,
                                    std::string_view inst_bytes,
                                    Instruction &inst,
                                    DecodingContext context) const {
  inst.pc = address;
  inst.next_pc = address + inst_bytes.size();  // Default fall-through.
  inst.branch_taken_pc = 0;
  inst.branch_not_taken_pc = 0;
  inst.has_branch_taken_delay_slot = false;
  inst.has_branch_not_taken_delay_slot = false;
  inst.arch_name = arch_name;
  inst.sub_arch_name = arch_name;
  inst.branch_taken_arch_name = arch_name;
  inst.arch = this;
  inst.category = Instruction::kCategoryInvalid;
  inst.operands.clear();
  inst.flows = Instruction::InvalidInsn();

  if (!context.HasValueForReg(std::string(kThumbModeRegName))) {
    return false;
  }


  return this->DecodeSleigh(address, inst_bytes, inst, std::move(context));
}

DecodingContext AArch32Arch::CreateInitialContext(void) const {
  return DecodingContext().PutContextReg(std::string(kThumbModeRegName), 0);
}


// TODO(pag): We pretend that these are singletons, but they aren't really!
Arch::ArchPtr Arch::GetAArch32(llvm::LLVMContext *context_, OSName os_name_,
                               ArchName arch_name_) {
  return std::make_unique<AArch32Arch>(context_, os_name_, arch_name_);
}


// TODO(pag): Eventually handle Thumb2 and unaligned addresses.
uint64_t AArch32Arch::MinInstructionAlign(const DecodingContext &cont) const {
  return IsThumb(cont) ? 2 : 4;
}

uint64_t AArch32Arch::MinInstructionSize(const DecodingContext &cont) const {
  return IsThumb(cont) ? 2 : 4;
}

// Maximum number of bytes in an instruction for this particular architecture.
uint64_t AArch32Arch::MaxInstructionSize(const DecodingContext &, bool) const {
  return 4;
}


bool AArch32Arch::DecodeSleigh(uint64_t address, std::string_view instr_bytes,
                               Instruction &inst,
                               DecodingContext context) const {
  return this->thumb_decoder.DecodeInstruction(address, instr_bytes, inst,
                                               context);
}

bool AArch32Arch::IsThumb(const DecodingContext &context) {
  return context.GetContextValue(std::string(kThumbModeRegName));
}

}  // namespace remill
