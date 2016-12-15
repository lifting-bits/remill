/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_EMULATOR_NATIVEEXEC_COMPILE_H_
#define TOOLS_VMILL_EMULATOR_NATIVEEXEC_COMPILE_H_

#include <string>

namespace llvm {

class Module;

}  // namespace llvm
namespace remill {
namespace vmill {

// Compile an LLVM module into a shared library.
void CompileToSharedObject(llvm::Module *module, const std::string &dest_path);

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_EMULATOR_NATIVEEXEC_COMPILE_H_
