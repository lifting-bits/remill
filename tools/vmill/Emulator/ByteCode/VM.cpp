/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <cstddef>

#include "remill/OS/FileSystem.h"

#include "tools/vmill/BC/Callback.h"
#include "tools/vmill/BC/Translator.h"

#include "tools/vmill/Emulator/ByteCode/Cache.h"
#include "tools/vmill/Emulator/ByteCode/Compiler.h"
#include "tools/vmill/Emulator/ByteCode/Interpreter.h"
#include "tools/vmill/Emulator/ByteCode/Operation.h"
#include "tools/vmill/Emulator/ByteCode/VM.h"

#include "tools/vmill/OS/System32.h"

namespace remill {
namespace vmill {

void ByteCodeVM::Compile(Process32 *process, const uint64_t pc) {
  DLOG(INFO)
      << "Lifting and compiling code for " << std::hex << pc;

  ByteReaderCallback byte_reader = [=] (uint64_t addr, uint8_t *bytes) {
    return process->TryReadExecutableByte(addr, bytes);
  };

  LiftedModuleCallback module_compiler = [=] (llvm::Module *module) {
    compiler->Compile(module);
  };

  translator->WithLiftedModule(pc, byte_reader, module_compiler);
}

ByteCodeVM::ByteCodeVM(uint64_t code_version_)
    : Emulator(code_version_),
      cache(ByteCodeCache::Create(code_version_)),
      constants(ConstantPool::Create(code_version_)),
      index(ByteCodeIndex::Create(cache)),
      compiler(ByteCodeCompiler::Create(index, cache, constants)) {}

ByteCodeVM::~ByteCodeVM(void) {
  delete compiler;
  delete constants;
  delete cache;
  delete index;
}

Emulator *ByteCodeVM::Create(uint64_t code_version_) {
  return new ByteCodeInterpreter(code_version_);
}

}  // namespace vmill
}  // namespace remill
