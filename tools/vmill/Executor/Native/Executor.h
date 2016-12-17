/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_EXECUTOR_NATIVE_EXECUTOR_H_
#define TOOLS_VMILL_EXECUTOR_NATIVE_EXECUTOR_H_

#include <string>
#include <unordered_map>

#include "tools/vmill/Executor/Executor.h"
#include "tools/vmill/Executor/Native/Runtime.h"

struct State;
struct Memory;

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

  // Path to the shared object file.
  std::string shared_object_path;

  // Pointer to the opaque shared object reference returned by `dlopen`.
  void *shared_object;

  // Maps native addresses to their lifted functions.
  std::unordered_map<uint64_t, LiftedFunction *> index;

 private:
  NativeExecutor(void) = delete;

  // Compiles or recompiles the bitcode in order to satisfy a new execution
  // request for code that we don't yet have lifted.
  void Recompile(Process32 *process, Thread32 *thread);
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_EXECUTOR_NATIVE_EXECUTOR_H_
