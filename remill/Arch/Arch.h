/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_ARCH_H_
#define REMILL_ARCH_ARCH_H_

#include <string>

struct ArchState;

namespace llvm {
class Module;
class BasicBlock;
class Function;
}  // namespace llvm.
namespace remill {

enum OSName : uint32_t;
enum ArchName : uint32_t;

class Instruction;

class Arch {
 public:
  virtual ~Arch(void);

  // Factory method for loading the correct architecture class for a given
  // operating system and architecture class.
  static const Arch *Get(OSName os, ArchName arch_name);

  // Converts an LLVM module object to have the right triple / data layout
  // information for the target architecture.
  virtual void PrepareModule(llvm::Module *mod) const = 0;

  // Decode an instruction.
  virtual Instruction *DecodeInstruction(
      uint64_t address,
      const std::string &instr_bytes) const = 0;

  virtual uint64_t ProgramCounter(const ArchState *state) const = 0;

  // Number of bits in an address.
  const OSName os_name;
  const ArchName arch_name;
  const unsigned address_size;

 protected:
  Arch(OSName os_name_, ArchName arch_name_);

 private:

  // Defined in `remill/Arch/X86/Arch.cpp`.
  static const Arch *GetX86(OSName os, ArchName arch_name);

  Arch(void) = delete;
};

const Arch *GetGlobalArch(void);

}  // namespace remill

#endif  // REMILL_ARCH_ARCH_H_
