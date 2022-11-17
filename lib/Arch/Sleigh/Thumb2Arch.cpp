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
#include <remill/Arch/AArch32/AArch32Base.h>
#include <remill/Arch/AArch32/ArchContext.h>
#include <remill/Arch/AArch32/Runtime/State.h>
#include <remill/Arch/Name.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Util.h>
#include <remill/BC/Version.h>
#include <remill/OS/OS.h>

#include "Arch.h"
#include "Thumb.h"

namespace remill {
namespace sleighthumb2 {
namespace {
const size_t kThumbInstructionSize = 2;
}

// TODO(Ian): support different arm versions
SleighThumb2Decoder::SleighThumb2Decoder(const remill::Arch &arch)
    : SleighDecoder(arch, "ARM8_le.sla", "ARMtTHUMB.pspec",
                    {{"ISAModeSwitch", std::string(kThumbModeRegName)}},
                    {{"CY", "C"}, {"NG", "N"}, {"ZR", "Z"}, {"OV", "V"}}) {}


void SleighThumb2Decoder::InitializeSleighContext(
    remill::sleigh::SingleInstructionSleighContext &ctxt) const {
  ctxt.GetContext().setVariableDefault("TMode", 1);
}

llvm::Value *
SleighThumb2Decoder::LiftPcFromCurrPc(llvm::IRBuilder<> &bldr,
                                      llvm::Value *curr_pc,
                                      size_t curr_insn_size) const {

  // PC on thumb points to the next instructions next.
  return bldr.CreateAdd(
      curr_pc,
      llvm::ConstantInt::get(curr_pc->getType(), kThumbInstructionSize * 2));
}

//TODO(Ian): this has code duplication with SleighX86Arch couldnt come up with a way to share implementation and not run into more
// annoying virtual inheretance from remill Arch. If we go back to virtual Arch then maybe we could just add another virtual inheratance of
// Arch. All of these are bad tho.
class SleighThumbArch : public AArch32ArchBase {
 public:
  SleighThumbArch(llvm::LLVMContext *context_, OSName os_name_,
                  ArchName arch_name_)
      : ArchBase(context_, os_name_, arch_name_),
        AArch32ArchBase(context_, os_name_, arch_name_),

        decoder(*this) {}

  virtual DecodingContext CreateInitialContext(void) const override {
    return DecodingContext().PutContextReg(std::string(kThumbModeRegName), 1);
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


  // TODO(pag): Eventually handle Thumb2 and unaligned addresses.
  uint64_t MinInstructionAlign(const DecodingContext &) const override {
    return 2;
  }

  uint64_t MinInstructionSize(const DecodingContext &) const override {
    return 2;
  }

  // Maximum number of bytes in an instruction for this particular architecture.
  uint64_t MaxInstructionSize(const DecodingContext &, bool) const override {
    return 4;
  }


 private:
  SleighThumb2Decoder decoder;
};


}  // namespace sleighthumb2

Arch::ArchPtr Arch::GetSleighThumb2(llvm::LLVMContext *context_,
                                    remill::OSName os_name_,
                                    remill::ArchName arch_name_) {
  return std::make_unique<sleighthumb2::SleighThumbArch>(context_, os_name_,
                                                         arch_name_);
}

}  // namespace remill
