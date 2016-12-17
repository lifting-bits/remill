/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_EXECUTOR_NATIVE_RUNTIME_H_
#define TOOLS_VMILL_EXECUTOR_NATIVE_RUNTIME_H_

#include <cstdint>

namespace remill {
namespace vmill {

enum class ExecutionStatus {
  kFunctionCall,
  kFunctionReturn,
  kJump,
  kAsyncHyperCall,
  kError
};

using LiftedFunction = ExecutionStatus (void *, void *, uint64_t);

}  // namespace vmill
}  // namespace remill
#endif  // TOOLS_VMILL_EXECUTOR_NATIVE_RUNTIME_H_
