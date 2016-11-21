/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_EMULATOR_BYTECODE_VM_H_
#define TOOLS_VMILL_EMULATOR_BYTECODE_VM_H_

#include "tools/vmill/Emulator/Emulator.h"

namespace remill {
namespace vmill {

class ByteCodeCache;
class ByteCodeCompiler;
class ByteCodeIndex;
class ByteCodeVM;
class ConstantPool;

class ByteCodeVM : public Emulator {
 public:
  virtual ~ByteCodeVM(void);

  static Emulator *Create(uint64_t code_version_);

  virtual Emulator::Status Emulate(Process32 *process, Thread32 *thread) = 0;

 protected:
  explicit ByteCodeVM(uint64_t code_version_);

  void Compile(Process32 *process, const uint64_t pc);

  ByteCodeCache * const cache;
  ConstantPool * const constants;
  ByteCodeIndex * const index;
  ByteCodeCompiler * const compiler;

 private:
  ByteCodeVM(void) = delete;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_EMULATOR_BYTECODE_VM_H_
