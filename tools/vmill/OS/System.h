/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_OS_SYSTEM_H_
#define TOOLS_VMILL_OS_SYSTEM_H_

#include <memory>
#include <vector>

#include "remill/Arch/Runtime/State.h"

namespace remill {
namespace vmill {

class Snapshot;
class SystemCallABI;

using SystemCallHandler = std::function<void(SystemCallABI &)>;



// A thread within a process.
class Thread {
 public:
  virtual ~Thread(void);

  virtual uint64_t NextProgramCounter(void) const = 0;
  virtual ArchState *MachineState(void) = 0;

  static std::unique_ptr<Thread> Create(const Snapshot *snapshot);

  const pid_t pid;
  const pid_t tid;

 protected:
  Thread(pid_t pid_, pid_t tid_);

 private:
  Thread(void) = delete;
};

class Process {
 public:
  static std::unique_ptr<Process> CreateNativeLinux(const Snapshot *snapshot);

  virtual ~Process(void);

  // Return an opaque pointer to memory, which can be used for implementing
  // memory access.
  virtual Memory *MachineMemory(void) = 0;

  // Kill the threads of this process; this destroys its current threads.
  void Kill(void);

  // Schedule the next runnable thread, and return it.
  Thread *ScheduleNextThread(void);

  // Process an asynchronous hypercall for the thread `thread`.
  virtual void HandleAsyncHyperCall(Thread *thread) = 0;

 protected:
  Process(const Snapshot *snapshot_, Thread *main_thread_);

  // Process a system call.
  virtual void HandleSystemCall(Thread *thread, SystemCallABI &abi) = 0;

  const Snapshot * const snapshot;

  std::vector<Thread *> threads;

 private:
  Process(void) = delete;
};


}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_OS_SYSTEM_H_
