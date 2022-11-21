#pragma once

#include <remill/Arch/Name.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Util.h>
#include <remill/BC/Version.h>
#include <remill/OS/OS.h>

#include "Arch.h"

namespace remill::sleighppc {

class SleighPPCDecoder final : public remill::sleigh::SleighDecoder {
 public:
  SleighPPCDecoder(const remill::Arch &arch);

  llvm::Value *LiftPcFromCurrPc(llvm::IRBuilder<> &bldr, llvm::Value *curr_pc,
                                size_t curr_insn_size) const override;

  void InitializeSleighContext(
      remill::sleigh::SingleInstructionSleighContext &ctxt) const override;
};

}  // namespace remill::sleighppc
