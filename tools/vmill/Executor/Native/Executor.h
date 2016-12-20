/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_EXECUTOR_NATIVE_EXECUTOR_H_
#define TOOLS_VMILL_EXECUTOR_NATIVE_EXECUTOR_H_

#include <string>

#include "tools/vmill/Executor/Executor.h"

namespace remill {
namespace vmill {

// Compile lifted code to native code and execute it natively.
class NativeExecutor : public Executor {
 public:
  using Executor::Executor;

  virtual ~NativeExecutor(void);

  // Execute the LLVM function `func` representing code in `process` at
  // the current program counter.
  virtual Flow Execute(Process *process, llvm::Function *func) = 0;

 private:
  NativeExecutor(void) = delete;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_EXECUTOR_NATIVE_EXECUTOR_H_
