/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>

#include "remill/Arch/Arch.h"

#include "tools/vmill/BC/Translator.h"
#include "tools/vmill/CFG/Decoder.h"
#include "tools/vmill/Executor/Executor.h"
#include "tools/vmill/Executor/Native/Executor.h"

DECLARE_string(os);
DECLARE_string(arch);

namespace remill {
namespace vmill {

Executor::Executor(CodeVersion code_version_)
    : arch(Arch::Create(GetOSName(FLAGS_os), GetArchName(FLAGS_arch))),
      translator(Translator::Create(code_version_, arch)),
      decoder(new InstructionDecoder(arch, translator)),
      code_version(code_version_) {}

Executor::~Executor(void) {
  delete translator;
  delete decoder;
  delete arch;
}

// Create a native code executor. This is a kind-of JIT compiler.
Executor *Executor::CreateNativeExecutor(CodeVersion code_version_) {
  return new NativeExecutor(code_version_);
}

}  // namespace vmill
}  // namespace remill
