/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include "tools/vmill/BC/Callback.h"
#include "tools/vmill/BC/Translator.h"

#include "tools/vmill/Emulator/NativeExec/Emulator.h"
#include "tools/vmill/Emulator/NativeExec/Compile.h"

#include "tools/vmill/OS/System32.h"

namespace remill {
namespace vmill {

NativeExecutor::~NativeExecutor(void) {}

NativeExecutor::NativeExecutor(CodeVersion code_version_)
    : Emulator(code_version_) {}

Emulator::Status NativeExecutor::Emulate(
    Process32 *process, Thread32 *thread) {

  const auto pc = thread->ProgramCounter();
  DLOG(INFO)
      << "Lifting and compiling code for " << std::hex << pc;

  ByteReaderCallback byte_reader = [=] (Addr64 addr, uint8_t *bytes) {
    return process->TryReadExecutableByte(static_cast<Addr32>(addr), bytes);
  };

  LiftedModuleCallback module_compiler = [=] (llvm::Module *module) {
    CompileToSharedObject(module, "/tmp/foo");
  };

  translator->WithLiftedModule(pc, byte_reader, module_compiler);
  return Emulator::kCannotContinue;
}

}  // namespace vmill
}  // namespace remill
