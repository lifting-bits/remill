/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_ARCH_H_
#define REMILL_ARCH_ARCH_H_

#include <string>

#include "remill/CFG/AutoAnalysis.h"
#include "remill/OS/OS.h"

namespace llvm {
class Module;
class BasicBlock;
class Function;
}  // namespace llvm.

namespace remill {
namespace cfg {
class Instr;
}  // namespace cfg

enum ArchName : unsigned {
  kArchInvalid,
  kArchX86,
  kArchAMD64
};

class Translator;

class Arch {
 public:
  virtual ~Arch(void);

  inline static const Arch *Create(OSName os, const std::string &arch_name) {
    return Create(os, GetName(arch_name));
  }

  // Factory method for loading the correct architecture class for a given
  // operating system and architecture class.
  static const Arch *Create(OSName os, ArchName arch_name);

  // Convert the string name of an architecture into a canonical form.
  static ArchName GetName(const std::string &arch_name);

  // Converts an LLVM module object to have the right triple / data layout
  // information for the target architecture.
  virtual llvm::Module *PrepareModule(llvm::Module *mod) const = 0;

  // Decode an instruction and lift it into a basic block.
  virtual void LiftInstructionIntoBlock(
      const Translator &translator,
      const cfg::Block &block,
      const cfg::Instr &instr,
      llvm::BasicBlock *basic_block) const = 0;

  // Return an arch-specific CFG analyzer.
  virtual AutoAnalysis &CFGAnalyzer(void) const = 0;

  // Number of bits in an address.
  const OSName os_name;
  const ArchName arch_name;
  const unsigned address_size;

 protected:
  Arch(OSName os_name_, ArchName arch_name_, unsigned address_size_);

 private:

  // Defined in `remill/Arch/X86/Arch.cpp`.
  static const Arch *CreateX86(
      OSName os, ArchName arch_name, unsigned address_size_);

  Arch(void) = delete;
};

}  // namespace remill

#endif  // MC_SEMA_ARCH_ARCH_H_
