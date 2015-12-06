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

enum ArchName {
  kArchX86,
  kArchAMD64
};

class Instr;

class Arch {
 public:
  static const Arch *Create(ArchName arch_name);

  static ArchName GetName(const std::string &arch_name);

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

 protected:
  Arch(unsigned address_size_);

 private:
  Arch(void) = delete;
};

}  // namespace mcsema

#endif  // MC_SEMA_ARCH_ARCH_H_
