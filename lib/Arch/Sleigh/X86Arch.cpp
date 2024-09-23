/*
 * Copyright (c) 2021-present Trail of Bits, Inc.
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
#include <llvm/IR/Attributes.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <remill/Arch/Context.h>
#include <remill/Arch/Name.h>
#include <remill/Arch/X86/X86Base.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>

#include "Arch.h"

namespace remill {
namespace sleigh::x86 {

class SleighX86Decoder final : public SleighDecoder {
 public:
  SleighX86Decoder() = delete;
  SleighX86Decoder(const remill::Arch &arch)
      : SleighDecoder(
            arch, kArchX86_SLEIGH == arch.arch_name ? "x86.sla" : "x86-64.sla",
            kArchX86_SLEIGH == arch.arch_name ? "x86.pspec" : "x86-64.pspec",
            ContextRegMappings({}, {}), {}) {}

  // The x86 default context is sufficient. No context register assignments are required.
  void
  InitializeSleighContext(uint64_t addr,
                          remill::sleigh::SingleInstructionSleighContext &ctxt,
                          const ContextValues &) const override {}

  llvm::Value *LiftPcFromCurrPc(llvm::IRBuilder<> &bldr, llvm::Value *curr_pc,
                                size_t curr_insn_size,
                                const DecodingContext &) const final {

    // PC on thumb points to the next instructions next.
    return bldr.CreateAdd(
        curr_pc, llvm::ConstantInt::get(curr_pc->getType(), curr_insn_size));
  }
};


class SleighX86Arch : public X86ArchBase {
 public:
  SleighX86Arch(llvm::LLVMContext *context_, OSName os_name_,
                ArchName arch_name_)
      : ArchBase(context_, os_name_, arch_name_),
        X86ArchBase(context_, os_name_, arch_name_),
        decoder(*this) {}

  virtual DecodingContext CreateInitialContext(void) const override {
    return DecodingContext();
  }

  virtual OperandLifter::OpLifterPtr
  DefaultLifter(const remill::IntrinsicTable &intrinsics) const override {
    return this->decoder.GetOpLifter();
  }

  virtual bool DecodeInstruction(uint64_t address, std::string_view instr_bytes,
                                 Instruction &inst,
                                 DecodingContext context) const override {
    return decoder.DecodeInstruction(address, instr_bytes, inst, context);
  }

 private:
  SleighX86Decoder decoder;
};

}  // namespace sleigh::x86
Arch::ArchPtr Arch::GetSleighX86(llvm::LLVMContext *context_, OSName os_name_,
                                 ArchName arch_name_) {
  return std::make_unique<sleigh::x86::SleighX86Arch>(context_, os_name_,
                                                      arch_name_);
}
}  // namespace remill
