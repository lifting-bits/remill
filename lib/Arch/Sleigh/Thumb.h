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
class SleighAArch32ThumbDecoder final : public remill::sleigh::SleighDecoder {
 public:
  SleighAArch32ThumbDecoder(const remill::Arch &arch);


  virtual llvm::Value *LiftPcFromCurrPc(llvm::IRBuilder<> &bldr, llvm::Value *,
                                        size_t curr_insn_size,
                                        const DecodingContext &) const final;

  void
  InitializeSleighContext(uint64_t addr,
                          remill::sleigh::SingleInstructionSleighContext &ctxt,
                          const ContextValues &context_values) const final;
};
}  // namespace sleighthumb2
}  // namespace remill
