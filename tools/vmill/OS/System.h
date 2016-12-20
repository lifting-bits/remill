/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_OS_SYSTEM_H_
#define TOOLS_VMILL_OS_SYSTEM_H_

#include "tools/vmill/BC/Callback.h"

namespace remill {
namespace vmill {

struct Runtime;

class Process {
 public:
  virtual ~Process(void);

  // Return the next program counter of code to execute.
  virtual uint64_t ProgramCounter(void) = 0;

  // Return an opaque pointer to a machine state, which includes things like
  // registers.
  virtual void *MachineState(void) = 0;

  // Return an opaque pointer to memory, which can be used for implementing
  // memory access.
  virtual void *Memory(void) = 0;

  // Return a function that can be used to try to read executable bytes from
  // a process's memory.
  virtual ByteReaderCallback ExecutableByteReader(void) = 0;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_OS_SYSTEM_H_
