/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_ARCH_H_
#define MCSEMA_ARCH_ARCH_H_

#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>

#include "mcsema/OS/OS.h"

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
  kArchInvalid,
  kArchX86,
  kArchAMD64
};

class Instr;

class Arch {
 public:
  inline static const Arch *Create(OSName os, const std::string &arch_name) {
    return Create(os, GetName(arch_name));
  }

  static const Arch *Create(OSName os, ArchName arch_name);

  static ArchName GetName(const std::string &arch_name);

  virtual ~Arch(void);

  // Decode an instruction and invoke a visitor with the decoded instruction.
  virtual void Decode(
      const cfg::Instr &instr,
      std::function<void(Instr &)> visitor) const = 0;

  // Converts an LLVM module object to have the right triple / data layout
  // information for the target architecture.
  virtual llvm::Module *ConvertModule(llvm::Module *mod) const = 0;

  // Number of bits in an address.
  const OSName os_name;
  const ArchName arch_name;
  const unsigned address_size;

 protected:
  Arch(OSName os_name_, ArchName arch_name_, unsigned address_size_);

 private:
  Arch(void) = delete;
};

}  // namespace mcsema

#endif  // MC_SEMA_ARCH_ARCH_H_
