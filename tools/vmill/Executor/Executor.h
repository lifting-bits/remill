/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_EXECUTOR_EXECUTOR_H_
#define TOOLS_VMILL_EXECUTOR_EXECUTOR_H_

#include <cstdint>
#include <memory>
#include <unordered_map>

namespace llvm {
class Function;
}  // namespace llvm
namespace remill {

class Arch;

namespace vmill {

class Decoder;
class Translator;

struct Runtime;

using Addr32 = uint32_t;
using Addr64 = uint64_t;

class Executor {
 public:
  enum Status {
    kStatusStoppedAtAsyncHyperCall,
    kStatusStoppedAtError
  };

  enum Flow {
    kFlowFunctionCall,
    kFlowFunctionReturn,
    kFlowJump,
    kFlowAsyncHyperCall,
    kFlowError
  };

  virtual ~Executor(void);

  // Create a process structure that is compatible with this executor.
  virtual std::unique_ptr<Process> CreateProcess(const Snapshot *snapshot) = 0;

  // Execute some code in `process`.
  Status Execute(Process *process);

  // Create a native code executor. This is a kind-of JIT compiler.
  static Executor *CreateNativeExecutor(const Arch * const arch_);

 protected:
  explicit Executor(const Runtime *runtime_,
                    const Arch * const arch_);

  // Execute the LLVM function `func` representing code in `process` at
  // the current program counter.
  virtual Flow Execute(Process *process, Thread *thread,
                       llvm::Function *func) = 0;

  // Lifted functions associated with each PC of native code.
  std::unordered_map<uint64_t, llvm::Function *> pc_to_func;
  std::unordered_map<llvm::Function *, uint64_t> func_to_pc;

 protected:

  // Runtime implementing the intrinsics.
  const Runtime * const runtime;

 private:
  // Lifts native code into LLVM bitcode.
  void LiftCodeAtProgramCounter(Process *process);

  // Updates `func_index` with whatever is in the lifted module.
  void UpdateFunctionIndex(void);

  // Architecture of code to be lifted.
  const Arch * const arch;

  // Reads bytes from a process' memory, and uses the `arch`-specific
  // instruction decoder to produce a CFG data structure. The CFG organizes
  // machine code instructions into basic blocks. The CFG is sent to the
  // `translator`, which lifts the basic blocks into LLVM bitcode (by using
  // Remill's lifter).
  Decoder * const decoder;

  // Lifts CFG structures into LLVM bitcode. This is a thin wrapper around
  // Remill's lifter, that caches the lifted bitcode to disk.
  Translator * const translator;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_EXECUTOR_EXECUTOR_H_
