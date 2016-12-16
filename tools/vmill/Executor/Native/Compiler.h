/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_EXECUTOR_NATIVE_COMPILER_H_
#define TOOLS_VMILL_EXECUTOR_NATIVE_COMPILER_H_

#include <string>

namespace llvm {
class Module;
}  // namespace llvm
namespace remill {
namespace vmill {
class Compiler {
 public:
  virtual ~Compiler(void);

  // Compile an LLVM module into a shared library.
  virtual void CompileToSharedObject(
      llvm::Module *module, const std::string &dest_path) = 0;

  static Compiler *Create(void);

 protected:
  Compiler(void);
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_EXECUTOR_NATIVE_COMPILER_H_
