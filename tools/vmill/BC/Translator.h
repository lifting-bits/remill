/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_BC_TRANSLATOR_H_
#define TOOLS_VMILL_BC_TRANSLATOR_H_

#include "tools/vmill/Executor/Executor.h"
#include "tools/vmill/BC/Callback.h"

namespace llvm {
class Module;
}  // namespace llvm
namespace remill {
namespace cfg {
class Module;
}  // namespace cfg
namespace vmill {

// Lifts CFG structures into LLVM bitcode. This is a thin wrapper around
// Remill's lifter, that caches the lifted bitcode to disk.
class Translator {
 public:
  virtual ~Translator(void);

  static Translator *Create(const Arch *source_arch_);

  // Execute a callback function on the module lifted by this translation.
  virtual void LiftCFG(const cfg::Module *cfg) = 0;

  // Run a callback on the lifted module code.
  virtual void VisitModule(LiftedModuleCallback callback) = 0;

 protected:
  explicit Translator(const Arch *source_arch_);

  // Arch of the code to be lifted.
  const Arch * const source_arch;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_BC_TRANSLATOR_H_
