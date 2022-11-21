#include "PPC.h"

namespace remill {

namespace sleighppc {

SleighPPCDecoder::SleighPPCDecoder(const remill::Arch &arch)
    : SleighDecoder(arch, "", "", {}, {}) {}

llvm::Value *SleighPPCDecoder::LiftPcFromCurrPc(llvm::IRBuilder<> &bldr,
                                                llvm::Value *curr_pc,
                                                size_t curr_insn_size) const {
  return nullptr;
}

void SleighPPCDecoder::InitializeSleighContext(
    remill::sleigh::SingleInstructionSleighContext &ctxt) const {}

}  // namespace sleighppc

Arch::ArchPtr Arch::GetSleighPPC(llvm::LLVMContext *context_,
                                 remill::OSName os_name_,
                                 remill::ArchName arch_name_) {
  return nullptr;
}

}  // namespace remill
