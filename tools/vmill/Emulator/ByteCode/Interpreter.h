/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_EMULATOR_BYTECODE_INTERPRETER_H_
#define TOOLS_VMILL_EMULATOR_BYTECODE_INTERPRETER_H_

#include "tools/vmill/Emulator/ByteCode/VM.h"

namespace remill {
namespace vmill {

class Memory32;

class ByteCodeInterpreter final : public ByteCodeVM {
 public:
  virtual ~ByteCodeInterpreter(void);

  Status Emulate(Process32 *process, Thread32 *thread) override;

 private:
  friend class ByteCodeVM;

  explicit ByteCodeInterpreter(uint64_t code_version_);

  ByteCodeInterpreter(void) = delete;

  Emulator::Status Interpret(Memory32 *memory, uint8_t *state, Operation *op);

  struct alignas(16) Stack {
    uint8_t data[4096 * 2];
  } stack;

  struct alignas(16) Data {
    uint64_t data[256];
  } data;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_EMULATOR_BYTECODE_INTERPRETER_H_
