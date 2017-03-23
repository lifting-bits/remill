/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_BC_TRANSLATOR_H_
#define TOOLS_VMILL_BC_TRANSLATOR_H_

#include <cstdint>
#include <memory>

namespace llvm {
class Module;
}  // namespace llvm
namespace remill {
namespace cfg {
class Module;
}  // namespace cfg
namespace vmill {

using CodeVersion = uint64_t;

// Lifts CFG structures into LLVM bitcode. This is a thin wrapper around
// Remill's lifter, that caches the lifted bitcode to disk.
class Translator {
 public:
  virtual ~Translator(void);

  static std::unique_ptr<Translator> Create(llvm::Module *module_);

  // Execute a callback function on the module lifted by this translation.
  virtual void LiftCFG(const cfg::Module *cfg) = 0;

 protected:
  Translator(void);

  // Arch of the code to be lifted.
  const Arch * const source_arch;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_BC_TRANSLATOR_H_
