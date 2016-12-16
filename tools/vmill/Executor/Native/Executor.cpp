/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include "tools/vmill/BC/Callback.h"
#include "tools/vmill/BC/Translator.h"

#include "tools/vmill/CFG/Decoder.h"

#include "tools/vmill/Executor/Native/Executor.h"
#include "tools/vmill/Executor/Native/Compiler.h"

#include "tools/vmill/OS/System32.h"

namespace remill {
namespace vmill {

NativeExecutor::~NativeExecutor(void) {
  delete compiler;
}

NativeExecutor::NativeExecutor(CodeVersion code_version_)
    : Executor(code_version_),
      compiler(Compiler::Create()) {}

Executor::Status NativeExecutor::Execute(
    Process32 *process, Thread32 *thread) {

  LiftedModuleCallback compile_module = [=] (llvm::Module *module) {
    compiler->CompileToSharedObject(module, "/tmp/foo");
  };

  CFGCallback lift_cfg = [=] (const cfg::Module *cfg) {
    translator->LiftCFG(cfg, compile_module);
  };

  ByteReaderCallback byte_reader = [=] (Addr64 addr, uint8_t *bytes) {
    return process->TryReadExecutableByte(static_cast<Addr32>(addr), bytes);
  };

  const auto pc = thread->ProgramCounter();
  DLOG(INFO)
      << "Lifting and compiling code for " << std::hex << pc;

  decoder->DecodeToCFG(pc, byte_reader, lift_cfg);

  return Executor::kCannotContinue;
}

}  // namespace vmill
}  // namespace remill
