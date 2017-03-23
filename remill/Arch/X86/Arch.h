/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_X86_ARCH_H_
#define REMILL_ARCH_X86_ARCH_H_

#include "remill/Arch/Arch.h"

namespace remill {

class X86Arch : public Arch {
 public:
  X86Arch(OSName os_name_, ArchName arch_name_);

  virtual ~X86Arch(void);

  void PrepareModule(llvm::Module *mod) const override;

  uint64_t ProgramCounter(const ArchState *state) const override;

  // Decode an instruction.
  Instruction *DecodeInstruction(
      uint64_t address, const std::string &instr_bytes) const override;

 private:
  X86Arch(void) = delete;
};

}  // namespace remill

#endif  // REMILL_ARCH_X86_ARCH_H_
