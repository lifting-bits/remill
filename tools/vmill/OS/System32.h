/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_OS_SYSTEM32_H_
#define TOOLS_VMILL_OS_SYSTEM32_H_

#include <cstdint>
#include <functional>
#include <vector>

#include "tools/vmill/Emulator/Emulator.h"
#include "remill/Arch/Runtime/HyperCall.h"

namespace remill {
namespace vmill {

class Memory32;
class Process32;
class Snapshot;
class SystemCall32;
class Thread32;

using SystemCallHandler = std::function<void(SystemCall32 &)>;

// 32-bit process abstraction/manager.
class Process32 {
 public:
  ~Process32(void);

  // Create a process from a snapshot.
  static Process32 *Create(const Snapshot *snapshot);

  // Process an asynchronous hypercall for the thread `thread`.
  void ProcessAsyncHyperCall(Thread32 *thread);

  // Kill this process; this destroys its current threads.
  void Kill(void);

  // Return a version number for the code. This version number is used to
  // represent the state of executable memory. If the contents of executable
  // memory change, then so should the code version.
  uint64_t CodeVersion(void);

  // Currently execution thread.
  Thread32 *CurrentThread(void) const;

  // Schedule the next runnable thread, and return it.
  Thread32 *NextThread(void);

  // Try to read the byte at address `addr` in the process memory. This will
  // return false if the byte is not readable or is not executable.
  bool TryReadExecutableByte(uint32_t addr, uint8_t *byte_val) const;

  Memory32 * const memory;

 protected:
  Process32(const Snapshot *snapshot_, Memory32 *memory_,
            Thread32 *main_thread_);

  void DoSystemCall(SystemCall32 &syscall);

  const Snapshot * const snapshot;
  std::vector<Thread32 *> threads;

 private:
  Process32(void) = delete;
};

// 32-bit thread state.
class Thread32 {
 public:
  virtual ~Thread32(void);

  virtual uint64_t ProgramCounter(void) const = 0;
  virtual uint8_t *MachineState(void) = 0;

  const pid_t pid;
  const pid_t tid;

 protected:
  Thread32(pid_t pid_, pid_t tid_);

  virtual AsyncHyperCall::Name GetHyperCall(void) const = 0;
  virtual int GetInterruptVector(void) const = 0;

  virtual void DoSystemCall(AsyncHyperCall::Name,
                            SystemCallHandler handler) = 0;

 private:
  friend class Process32;

  static Thread32 *Create(const Snapshot *snapshot);

  Thread32(void) = delete;
};

// A memory map within the address space.
struct MemoryMap32 {
  uint32_t base_address;
  uint32_t limit_address;

  // Permissions.
  uint64_t is_read:1;
  uint64_t is_write:1;
  uint64_t is_exec:1;

  // State of the pages.
  uint64_t can_read:1;
  uint64_t can_write:1;
  uint64_t can_exec:1;

  // Hash of the page map.
  uint64_t hash:58;

} __attribute__((packed));

static_assert(sizeof(MemoryMap32) == 16, "Invalid packing of MemoryMap32");

// Virtual memory implementation for 32-bit applications.
class Memory32 final {
 public:

  // Create an empty virtual address space.
  static Memory32 *Create(const Snapshot *snapshot);

  ~Memory32(void);

  inline uint8_t *RawByteAddress(uint64_t addr) const {
    return reinterpret_cast<uint8_t *>(
        base_address + static_cast<uintptr_t>(static_cast<uint32_t>(addr)));
  }

  inline uint16_t *RawWordAddress(uint64_t addr) const {
    return reinterpret_cast<uint16_t *>(
        base_address + static_cast<uintptr_t>(static_cast<uint32_t>(addr)));
  }

  inline uint32_t *RawDwordAddress(uint64_t addr) const {
    return reinterpret_cast<uint32_t *>(
        base_address + static_cast<uintptr_t>(static_cast<uint32_t>(addr)));
  }

  inline uint64_t *RawQwordAddress(uint64_t addr) const {
    return reinterpret_cast<uint64_t *>(
        base_address + static_cast<uintptr_t>(static_cast<uint32_t>(addr)));
  }

 protected:
  friend class Process32;
  friend class Thread32;

  explicit Memory32(void *addr, const std::vector<MemoryMap32> &maps_);

  const uintptr_t base_address;
  const uintptr_t limit_address;

  std::vector<MemoryMap32> maps;

 private:
  Memory32(void) = delete;
};

class SystemCall32 {
 public:
  virtual ~SystemCall32(void) {}

  virtual void SetReturn(int ret_val) const = 0;

  virtual int GetSystemCallNum(void) const = 0;

  inline bool TryGetInt32(int arg_num, int32_t *val) const {
    return TryGetArgValue(arg_num, sizeof(int32_t), val);
  }

  inline bool TryGetUInt32(int arg_num, uint32_t *val) const {
    return TryGetArgValue(arg_num, sizeof(uint32_t), val);
  }

  inline bool TryGetInt64(int arg_num, int64_t *val) const {
    return TryGetArgValue(arg_num, sizeof(int64_t), val);
  }

  inline bool TryGetUInt64(int arg_num, uint64_t *val) const {
    return TryGetArgValue(arg_num, sizeof(uint64_t), val);
  }

 protected:
  virtual bool TryGetArgValue(
      int arg_num, size_t value_size, void *value) const = 0;

  SystemCall32(void) = default;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_OS_SYSTEM32_H_
