/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_EXECUTOR_EXECUTOR_H_
#define TOOLS_VMILL_EXECUTOR_EXECUTOR_H_

#include <cstdint>
#include <unordered_map>

namespace llvm {
class Function;
}  // namespace llvm
namespace remill {

class Arch;

namespace vmill {

class Decoder;
class Process;
struct Runtime;
class Translator;

using Addr32 = uint32_t;
using Addr64 = uint64_t;
using CodeVersion = uint64_t;

class Executor {
 public:
  enum Status {
    kStatusCannotContinue,
    kStatusPaused,
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

  // Execute some code in `process`.
  Status Execute(Process *process);

  // Create a native code executor. This is a kind-of JIT compiler.
  static Executor *CreateNativeExecutor(const Arch * const arch_,
                                        CodeVersion code_version_);

 protected:
  explicit Executor(const Runtime *runtime_,
                    const Arch * const arch_,
                    CodeVersion code_version_);

  // Execute the LLVM function `func` representing code in `process` at
  // the current program counter.
  virtual Flow Execute(Process *process, llvm::Function *func) = 0;

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
  const Decoder * const decoder;

  // Lifts CFG structures into LLVM bitcode. This is a thin wrapper around
  // Remill's lifter, that caches the lifted bitcode to disk.
  Translator * const translator;

  // Version of the code managed by this executor.
  const CodeVersion code_version;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_EXECUTOR_EXECUTOR_H_
