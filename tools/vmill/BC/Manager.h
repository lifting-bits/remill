/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_BC_MANAGER_H_
#define TOOLS_VMILL_BC_MANAGER_H_

#include <memory>

namespace remill {

class Arch;

namespace vmill {

class Decoder;
class Translator;

class BitcodeManager {
 public:
  explicit BitcodeManager(const Arch *arch);

 private:
  BitcodeManager(void) = delete;

  // Reads bytes from a process' memory, and uses the `arch`-specific
  // instruction decoder to produce a CFG data structure. The CFG organizes
  // machine code instructions into basic blocks. The CFG is sent to the
  // `translator`, which lifts the basic blocks into LLVM bitcode (by using
  // Remill's lifter).
  const std::unique_ptr<Decoder> decoder;

  // Lifts CFG structures into LLVM bitcode. This is a thin wrapper around
  // Remill's lifter, that caches the lifted bitcode to disk.
  const std::unique_ptr<Translator> translator;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_BC_MANAGER_H_
