/*
 * Copyright (c) 2026 Trail of Bits, Inc.
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

#include <remill/Arch/ArchBase.h>

#include "Arch.h"

namespace remill {

class SleighSPARC64Decoder final : public remill::sleigh::SleighDecoder {
 public:
  explicit SleighSPARC64Decoder(const remill::Arch &arch);

  llvm::Value *LiftPcFromCurrPc(llvm::IRBuilder<> &bldr, llvm::Value *curr_pc,
                                size_t curr_insn_size,
                                const DecodingContext &) const final;

  void
  InitializeSleighContext(uint64_t addr,
                          remill::sleigh::SingleInstructionSleighContext &ctxt,
                          const ContextValues &context_values) const final;
};

// 64-bit SPARC (SPARC V9) using Ghidra's `SparcV9_64.sla`.
class SPARC64Arch final : public virtual ArchBase {
 public:
  SPARC64Arch(llvm::LLVMContext *context_, OSName os_name_,
              ArchName arch_name_);

  virtual ~SPARC64Arch(void) = default;

  std::string_view StackPointerRegisterName(void) const final;
  std::string_view ProgramCounterRegisterName(void) const final;

  uint64_t MinInstructionAlign(const DecodingContext &) const final;
  uint64_t MinInstructionSize(const DecodingContext &) const final;
  uint64_t MaxInstructionSize(const DecodingContext &,
                              bool permit_fuse_idioms) const final;

  llvm::CallingConv::ID DefaultCallingConv(void) const final;
  llvm::Triple Triple(void) const final;
  llvm::DataLayout DataLayout(void) const final;
  bool MemoryAccessIsLittleEndian(void) const final;

  void PopulateRegisterTable(void) const final;
  void FinishLiftedFunctionInitialization(llvm::Module *module,
                                          llvm::Function *bb_func) const final;

  DecodingContext CreateInitialContext(void) const final;
  OperandLifter::OpLifterPtr
  DefaultLifter(const remill::IntrinsicTable &intrinsics) const final;
  bool DecodeInstruction(uint64_t address, std::string_view instr_bytes,
                         Instruction &inst,
                         DecodingContext context) const final;

 private:
  SleighSPARC64Decoder decoder;
};

}  // namespace remill
