/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_EXECUTOR_EXECUTOR_H_
#define TOOLS_VMILL_EXECUTOR_EXECUTOR_H_

#include <cstdint>

namespace remill {

class Arch;

namespace vmill {

class InstructionDecoder;
class Process32;
class Thread32;
class Translator;

using Addr32 = uint32_t;
using Addr64 = uint64_t;
using CodeVersion = uint64_t;

class Executor {
 public:
  enum Status {
    kCannotContinue,
    kPaused,
    kStoppedAtAsyncHyperCall,
    kStoppedAtError
  };

  virtual ~Executor(void);

  virtual Status Execute(Process32 *process, Thread32 *thread) = 0;

  // Create a native code executor. This is a kind-of JIT compiler.
  static Executor *CreateNativeExecutor(CodeVersion code_version_);

 protected:
  explicit Executor(CodeVersion code_version_);

  const Arch * const arch;

  Translator * const translator;

  const InstructionDecoder * const decoder;

  const CodeVersion code_version;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_EXECUTOR_EXECUTOR_H_
