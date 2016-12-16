/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_EXECUTOR_NATIVE_EXECUTOR_H_
#define TOOLS_VMILL_EXECUTOR_NATIVE_EXECUTOR_H_

#include "tools/vmill/Executor/Executor.h"

namespace remill {
namespace vmill {

class Compiler;

class NativeExecutor : public Executor {
 public:
  virtual ~NativeExecutor(void);

  explicit NativeExecutor(CodeVersion code_version_);

  Status Execute(Process32 *process, Thread32 *thread) override;

 protected:
  Compiler *compiler;

 private:
  NativeExecutor(void) = delete;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_EXECUTOR_NATIVE_EXECUTOR_H_
