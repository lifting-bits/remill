/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_ARCH_H_
#define MCSEMA_ARCH_ARCH_H_

#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>

namespace llvm {
class Module;
class BasicBlock;
class Function;
}  // namespace llvm.

namespace mcsema {
namespace cfg {
class Instr;
}  // namespace cfg

#if 0
// Generic register type. For example, a XED register for x86 falls into this
// type.
using ArchReg = unsigned;

// X86-specific McSema register type.
namespace x86 {
enum class Reg : unsigned;
}  // namespace x86

// Cross-arch McSema register type.
//
// TODO(pag): Add more arch register types here (e.g. `arm::Reg`).
union McReg {

  inline McReg(const McReg &reg_)
      : flat(reg_.flat) {}

  inline McReg(unsigned flat_)
      : flat(flat_) {}

  inline McReg(x86::Reg reg_)
      : reg_x86(reg_) {}

  const unsigned flat;
  const x86::Reg reg_x86;
};
#endif

class Instr;

class Arch {
 public:
  Arch(unsigned address_size_);
  virtual ~Arch(void);

  // Decode an instruction and invoke a visitor with the decoded instruction.
  virtual void Decode(
      const cfg::Instr &instr,
      std::function<void(Instr &)> visitor) const = 0;

  // Creates an LLVM module object for the lifted code. This module is based on
  // an arch-specific template, found in the `State.inc` file.
  virtual llvm::Module *CreateModule(void) const = 0;

  // Number of bits in an address.
  const unsigned address_size;

 private:
  Arch(void) = delete;
};

Arch *CreateArch(std::string arch_name);

}  // namespace mcsema

#endif  // MC_SEMA_ARCH_ARCH_H_
