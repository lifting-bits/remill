/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_OS_SYSTEM_H_
#define TOOLS_VMILL_OS_SYSTEM_H_

#include <vector>

#include "remill/Arch/Runtime/HyperCall.h"

#include "tools/vmill/BC/Callback.h"

namespace remill {
namespace vmill {

using CodeVersion = uint64_t;

class Snapshot;

class Thread {
 public:
  virtual ~Thread(void);

  virtual uint64_t NextProgramCounter(void) const = 0;

  virtual AsyncHyperCall::Name PendingHyperCall(void) const = 0;

  virtual int PendingInterruptVector(void) const = 0;

  virtual void *MachineState(void) = 0;

  const pid_t pid;
  const pid_t tid;

 protected:
  Thread(pid_t pid_, pid_t tid_);

 private:
  Thread(void) = delete;
};

class Process {
 public:
  thread_local static Process *gCurrent;

  static Process *Create(const Snapshot *snapshot);

  virtual ~Process(void);

  // Return the next program counter of code to execute.
  uint64_t NextProgramCounter(void) const;

  // Return an opaque pointer to a machine state, which includes things like
  // registers.
  virtual void *MachineState(void) = 0;

  // Return an opaque pointer to memory, which can be used for implementing
  // memory access.
  virtual void *Memory(void) = 0;

  // Kill the threads of this process; this destroys its current threads.
  void Kill(void);

  // Currently execution thread;
  Thread *CurrentThread(void) const;

  // Schedule the next runnable thread, and return it.
  Thread *ScheduleNextThread(void);

  // Return a version number for the code. This version number is used to
  // represent the state of executable memory. If the contents of executable
  // memory change, then so should the code version.
  virtual CodeVersion CodeVersion(void) = 0;

  // Process an asynchronous hypercall for the thread `thread`.
  virtual void HandleAsyncHyperCall(Thread *thread) = 0;

  // Return a function that can be used to try to read executable bytes from
  // a process's memory.
  virtual ByteReaderCallback ExecutableByteReader(void) = 0;

  template <typename T>
  inline bool TryRead(uintptr_t addr, T *val) const {
    return TryReadBytes(addr, val, sizeof(T));
  }

  template <typename T>
  inline bool TryWrite(uintptr_t addr, const T &val) const {
    return TryWriteBytes(addr, &val, sizeof(T));
  }

  // Read data from the emulated process.
  inline bool TryReadByte(uintptr_t addr, uint8_t *byte_val) const {
    return TryRead(addr, byte_val);
  }

  inline bool TryReadWord(uintptr_t addr, uint16_t *word_val) const {
    return TryRead(addr, word_val);
  }

  inline bool TryReadDword(uintptr_t addr, uint32_t *dword_val) const {
    return TryRead(addr, dword_val);
  }

  inline bool TryReadQword(uintptr_t addr, uint64_t *qword_val) const {
    return TryRead(addr, qword_val);
  }

  // Write data to the emulated process.
  inline bool TryWriteByte(uintptr_t addr, uint8_t byte_val) const {
    return TryWrite(addr, byte_val);
  }

  inline bool TryWriteWord(uintptr_t addr, uint16_t word_val) const {
    return TryWrite(addr, word_val);
  }

  inline bool TryWriteDword(uintptr_t addr, uint32_t dword_val) const {
    return TryWrite(addr, dword_val);
  }

  inline bool TryWriteQword(uintptr_t addr, uint64_t qword_val) const {
    return TryWrite(addr, qword_val);
  }

 protected:
  Process(const Snapshot *snapshot_, Thread *main_thread_);

  virtual bool TryReadBytes(
      uintptr_t addr, void *val, size_t num_bytes) const = 0;

  virtual bool TryWriteBytes(
      uintptr_t addr, const void *val, size_t num_bytes) const = 0;


  const Snapshot * const snapshot;

  std::vector<Thread *> threads;

 private:
  Process(void) = delete;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_OS_SYSTEM_H_
