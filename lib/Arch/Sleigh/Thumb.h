#pragma once

#include <remill/Arch/AArch32/AArch32Base.h>
#include <remill/Arch/AArch32/Runtime/State.h>
#include <remill/Arch/Name.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Util.h>
#include <remill/BC/Version.h>
#include <remill/OS/OS.h>

#include "Arch.h"


namespace remill {

namespace sleighthumb2 {
class SleighThumb2Decoder final : public remill::sleigh::SleighDecoder {
 public:
  SleighThumb2Decoder(const remill::Arch &arch);


  virtual llvm::Value *LiftPcFromCurrPc(llvm::IRBuilder<> &bldr, llvm::Value *,
                                        size_t curr_insn_size) const final;

  void
  InitializeSleighContext(remill::sleigh::SingleInstructionSleighContext &ctxt,
                          const ContextValues &context_values) const final;
};
}  // namespace sleighthumb2
}  // namespace remill
