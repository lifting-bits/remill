/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_BC_CALLBACK_H_
#define TOOLS_VMILL_BC_CALLBACK_H_

#include <cstdint>
#include <functional>

namespace llvm {
class Function;
class Module;
}  // namespace llvm
namespace remill {
namespace vmill {

using ByteReaderCallback = std::function<bool(uint64_t, uint8_t *)>;

using LiftedFunctionCallback = std::function<void(uint64_t, llvm::Function *)>;

using LiftedModuleCallback = std::function<void(llvm::Module *)>;

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_BC_CALLBACK_H_
