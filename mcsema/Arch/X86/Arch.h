/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_X86_ARCH_H_
#define MCSEMA_ARCH_X86_ARCH_H_

#include "mcsema/Arch/Arch.h"
#include "mcsema/Arch/X86/AutoAnalysis.h"

namespace mcsema {
namespace x86 {

class X86Arch : public Arch {
 public:
  virtual ~X86Arch(void);

  virtual llvm::Module *PrepareModule(llvm::Module *mod) const override;

  // Decode an instruction and lift it into a basic block.
  virtual void LiftInstructionIntoBlock(
      const Translator &translator,
      const cfg::Block &block, const cfg::Instr &instr,
      llvm::BasicBlock *B) const override;

  // Return an arch-specific CFG analyzer.
  virtual AutoAnalysis &CFGAnalyzer(void) const override;

 protected:
  friend class Arch;

  X86Arch(OSName os_name_, ArchName arch_name_, unsigned address_size_);

 private:
  X86Arch(void) = delete;

  mutable RegisterAnalysis analysis;
};

}  // namespace x86
}  // namespace mcsema

#endif  // MCSEMA_ARCH_X86_ARCH_H_
