/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_BC_TRANSLATOR_H_
#define TOOLS_VMILL_BC_TRANSLATOR_H_

#include "tools/vmill/BC/Callback.h"
#include "tools/vmill/Emulator/Emulator.h"

namespace llvm {
class Function;
class Module;
}  // namespace llvm
namespace remill {
namespace vmill {

// Handles translating binary code to bitcode, and caching that bitcode.
class Translator {
 public:
  virtual ~Translator(void);

  // Create a new translation engine for a given version of the code in
  // memory. Code version changes happen due to self-modifying code, or
  // runtime code loading.
  static Translator *Create(CodeVersion code_version_);

  // Execute a callback function on the module lifted by this translation.
  virtual void WithLiftedModule(
      const uint64_t pc,
      ByteReaderCallback byte_reader,
      LiftedModuleCallback on_module) = 0;

 protected:
  explicit Translator(CodeVersion code_version_);

  // An abstract version number for code handled by this translation engine.
  // Runtime code modification change the version, and so a higher-level
  // system is responsible for creating a new translator to handle the
  // modified code.
  CodeVersion code_version;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_BC_TRANSLATOR_H_
