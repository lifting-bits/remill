/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_BC_CALLBACK_H_
#define TOOLS_VMILL_BC_CALLBACK_H_

#include <cstdint>
#include <functional>

namespace llvm {
class Module;
}  // namespace llvm
namespace remill {
namespace cfg {
class Module;
}  // namespace cfg
namespace vmill {

using CFGCallback = std::function<void(const cfg::Module *)>;

using ByteReaderCallback = std::function<bool(uint64_t, uint8_t *)>;

using LiftedModuleCallback = std::function<void(llvm::Module *)>;

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_BC_CALLBACK_H_
