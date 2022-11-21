/*
 * Copyright (c) 2022-present Trail of Bits, Inc.
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

#include "PPC.h"

namespace remill {

namespace sleighppc {

SleighPPCDecoder::SleighPPCDecoder(const remill::Arch &arch)
    : SleighDecoder(arch, "ppc_32_be.sla", "ppc_32.pspec", {}, {}) {}

llvm::Value *SleighPPCDecoder::LiftPcFromCurrPc(llvm::IRBuilder<> &bldr,
                                                llvm::Value *curr_pc,
                                                size_t curr_insn_size) const {
  return nullptr;
}

void SleighPPCDecoder::InitializeSleighContext(
    remill::sleigh::SingleInstructionSleighContext &ctxt) const {}

class SleighPPCArch : public ArchBase {
 public:
  SleighPPCArch(llvm::LLVMContext *context_, OSName os_name_,
                ArchName arch_name_)
      : ArchBase(context_, os_name_, arch_name_),
        decoder(*this) {}
  virtual ~SleighPPCArch() = default;

  DecodingContext CreateInitialContext(void) const override {
    return DecodingContext();
  }

  std::string_view StackPointerRegisterName(void) const override {
    return "r1";
  }

  std::string_view ProgramCounterRegisterName(void) const override {
    // TODO(alex): PPC doesn't expose this. Need to figure out what to do here.
    return "";
  }

  OperandLifter::OpLifterPtr
  DefaultLifter(const remill::IntrinsicTable &intrinsics) const override {
    return this->decoder.GetOpLifter();
  }

  bool DecodeInstruction(uint64_t address, std::string_view instr_bytes,
                         Instruction &inst,
                         DecodingContext context) const override {
    return decoder.DecodeInstruction(address, instr_bytes, inst, context);
  }

  uint64_t MinInstructionAlign(const DecodingContext &) const override {
    return 4;
  }

  uint64_t MinInstructionSize(const DecodingContext &) const override {
    return 4;
  }

  uint64_t MaxInstructionSize(const DecodingContext &, bool) const override {
    return 4;
  }

  llvm::CallingConv::ID DefaultCallingConv(void) const override {
    return llvm::CallingConv::C;
  }

  llvm::Triple Triple(void) const override {
    auto triple = BasicTriple();
    triple.setArch(llvm::Triple::ppc);
    return triple;
  }

  llvm::DataLayout DataLayout(void) const override {
    return llvm::DataLayout("");
  }

  void PopulateRegisterTable(void) const override {}

  void
  FinishLiftedFunctionInitialization(llvm::Module *module,
                                     llvm::Function *bb_func) const override {}

 private:
  SleighPPCDecoder decoder;
};

}  // namespace sleighppc

Arch::ArchPtr Arch::GetSleighPPC(llvm::LLVMContext *context_,
                                 remill::OSName os_name_,
                                 remill::ArchName arch_name_) {
  return std::make_unique<sleighppc::SleighPPCArch>(context_, os_name_,
                                                    arch_name_);
}

}  // namespace remill
