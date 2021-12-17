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

#pragma once

#include "../Arch.h"  // For `Arch` and `ArchImpl`.

namespace remill {
class AArch32Arch final : public Arch {
 public:
  AArch32Arch(llvm::LLVMContext *context_, OSName os_name_,
              ArchName arch_name_);

  virtual ~AArch32Arch(void);

  // Returns the name of the stack pointer register.
  std::string_view StackPointerRegisterName(void) const final;

  // Returns the name of the program counter register.
  std::string_view ProgramCounterRegisterName(void) const final;

  // Decode an instuction.
  bool DecodeInstruction(uint64_t address, std::string_view inst_bytes,
                         Instruction &inst) const final;

  // Align/Minimum/Maximum number of bytes in an instruction.
  uint64_t MinInstructionAlign(void) const final;
  uint64_t MinInstructionSize(void) const final;
  uint64_t MaxInstructionSize(bool permit_fuse_idioms) const final;

  llvm::Triple Triple(void) const final;
  llvm::DataLayout DataLayout(void) const final;

  // Default calling convention for this architecture.
  llvm::CallingConv::ID DefaultCallingConv(void) const final;

  // Populate the table of register information.
  void PopulateRegisterTable(void) const final;

  // Populate a just-initialized lifted function function with architecture-
  // specific variables.
  void FinishLiftedFunctionInitialization(
      llvm::Module *module, llvm::Function *bb_func) const final;

 private:
  AArch32Arch(void) = delete;
};

}  // namespace remill
