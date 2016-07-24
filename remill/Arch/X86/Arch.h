/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_X86_ARCH_H_
#define REMILL_ARCH_X86_ARCH_H_

#include "remill/Arch/Arch.h"
#include "remill/Arch/X86/AutoAnalysis.h"

namespace remill {
namespace x86 {

class X86Arch : public Arch {
 public:
  X86Arch(OSName os_name_, ArchName arch_name_, unsigned address_size_);

  virtual ~X86Arch(void);

  virtual llvm::Module *PrepareModule(llvm::Module *mod) const override;

  // Decode an instruction and lift it into a basic block.
  virtual void LiftInstructionIntoBlock(
      const Translator &translator,
      const cfg::Block &block,
      const cfg::Instr &instr,
      llvm::BasicBlock *basic_block) const override;

  // Return an arch-specific CFG analyzer.
  virtual AutoAnalysis &CFGAnalyzer(void) const override;

 private:
  X86Arch(void) = delete;

  mutable RegisterAnalysis analysis;
};

}  // namespace x86
}  // namespace remill

#endif  // REMILL_ARCH_X86_ARCH_H_
