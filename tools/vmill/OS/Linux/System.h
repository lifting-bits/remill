/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_OS_LINUX_SYSTEM_H_
#define TOOLS_VMILL_OS_LINUX_SYSTEM_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "tools/vmill/Executor/Executor.h"
#include "tools/vmill/OS/System.h"

namespace remill {
namespace vmill {

class LinuxMemory;
class LinuxProcess;
class LinuxThread;
class Snapshot;

// 32-bit process abstraction/manager.
class LinuxProcess : public Process {
 public:
  virtual ~LinuxProcess(void);

  // Create a process from a snapshot.
  static std::unique_ptr<Process> Create(const Snapshot *snapshot);

  // Return an opaque pointer to memory, which can be used for implementing
  // memory access.
  Memory *MachineMemory(void) override;

  // Process an asynchronous hypercall for the thread `thread`.
  void HandleAsyncHyperCall(Thread *thread) override;

  LinuxMemory * const memory;

 protected:
  LinuxProcess(const Snapshot *snapshot_, LinuxMemory *memory_,
               LinuxThread *main_thread_);

  void DoSystemCall(SystemCallABI &syscall);

 private:
  LinuxProcess(void) = delete;
};

// 32-bit thread state.
class LinuxThread : public Thread {
 public:
  virtual ~LinuxThread(void);

 protected:
  using Thread::Thread;

  virtual void DoSystemCall(Process *process, AsyncHyperCall::Name,
                            SystemCallHandler handler) = 0;

  static std::unique_ptr<Thread> Create(const Snapshot *snapshot);

 private:
  static std::unique_ptr<Thread> Create32(const Snapshot *snapshot);

 private:
  LinuxThread(void) = delete;
};

// Virtual memory implementation for 32-bit applications.
class LinuxMemory : public Memory {
 public:
  // Create an empty virtual address space.
  static LinuxMemory *Create(const Snapshot *snapshot);

  virtual ~LinuxMemory(void);

 protected:
  bool TryReadBytes(uint64_t addr, void *data, size_t size) const override;
  bool TryWriteBytes(uint64_t addr, const void *data,
                     size_t size) const override;

  // Query the process's virtual memory map to get information about some
  // mapped pages.
  const AddressRange *QueryMemoryImpl(uint64_t address) const override;


  explicit LinuxMemory(const std::vector<AddressRange> &maps_);

  std::vector<AddressRange> maps;

 private:
  LinuxMemory(void) = delete;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_OS_LINUX_SYSTEM_H_
