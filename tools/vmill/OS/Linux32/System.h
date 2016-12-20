/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_OS_LINUX32_SYSTEM_H_
#define TOOLS_VMILL_OS_LINUX32_SYSTEM_H_

#include <cstdint>
#include <functional>
#include <vector>

#include "remill/Arch/Runtime/HyperCall.h"

#include "tools/vmill/Executor/Executor.h"
#include "tools/vmill/OS/System.h"

namespace remill {
namespace vmill {

class Memory32;
class Process32;
class Snapshot;
class SystemCall32;
class Thread32;

using SystemCallHandler = std::function<void(SystemCall32 &)>;

// 32-bit process abstraction/manager.
class Process32 : public Process {
 public:
  virtual ~Process32(void);

  // Create a process from a snapshot.
  static Process32 *Create(const Snapshot *snapshot);

  // Return a function that can be used to try to read executable bytes from
  // a process's memory.
  ByteReaderCallback ExecutableByteReader(void) override;

  // Return the next program counter of code to execute.
  uint64_t ProgramCounter(void) override;

  // Return the machine state to be executed.
  void *MachineState(void) override;

  // Return an opaque pointer to memory, which can be used for implementing
  // memory access.
  void *Memory(void) override;

  // Process an asynchronous hypercall for the thread `thread`.
  void ProcessAsyncHyperCall(Thread32 *thread);

  // Kill this process; this destroys its current threads.
  void Kill(void);

  // Return a version number for the code. This version number is used to
  // represent the state of executable memory. If the contents of executable
  // memory change, then so should the code version.
  CodeVersion CodeVersion(void);

  // Currently execution thread.
  Thread32 *CurrentThread(void) const;

  // Schedule the next runnable thread, and return it.
  Thread32 *ScheduleNextThread(void);

  // Try to read the byte at address `addr` in the process memory. This will
  // return false if the byte is not readable or is not executable.
  bool TryReadExecutableByte(Addr32 addr, uint8_t *byte_val) const;

  // Read data from the emulated process.
  bool TryReadByte(Addr32 addr, uint8_t *byte_val) const;
  bool TryReadWord(Addr32 addr, uint16_t *word_val) const;
  bool TryReadDword(Addr32 addr, uint32_t *dword_val) const;
  bool TryReadQword(Addr32 addr, uint64_t *qword_val) const;

  // Write data to the emulated process.
  bool TryWriteByte(Addr32 addr, uint8_t byte_val) const;
  bool TryWriteWord(Addr32 addr, uint16_t word_val) const;
  bool TryWriteDword(Addr32 addr, uint32_t dword_val) const;
  bool TryWriteQword(Addr32 addr, uint64_t qword_val) const;

  template <typename T>
  bool TryRead(Addr32 addr, T *val) const {
    auto val_bytes = reinterpret_cast<uint8_t *>(val);
    for (Addr32 i = 0; i < sizeof(T); ++i) {
      if (!TryReadByte(addr + i, &(val_bytes[i]))) {
        return false;
      }
    }
    return true;
  }

  template <typename T>
  bool TryWrite(Addr32 addr, const T &val) const {
    auto val_bytes = reinterpret_cast<const uint8_t *>(&val);
    for (Addr32 i = 0; i < sizeof(T); ++i) {
      if (!TryWriteByte(addr + i, val_bytes[i])) {
        return false;
      }
    }
    return true;
  }

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
  virtual void *MachineState(void) = 0;

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

  inline uint8_t *UnsafeBytePtr(Addr32 addr) const {
    return reinterpret_cast<uint8_t *>(addr);
  }

  inline uint16_t *UnsafeWordPtr(Addr32 addr) const {
    return reinterpret_cast<uint16_t *>(addr);
  }

  inline uint32_t *UnsafeDwordPtr(Addr32 addr) const {
    return reinterpret_cast<uint32_t *>(addr);
  }

  inline uint64_t *UnsafeQwordPtr(Addr32 addr) const {
    return reinterpret_cast<uint64_t *>(addr);
  }

 protected:
  friend class Process32;
  friend class Thread32;

  explicit Memory32(const std::vector<MemoryMap32> &maps_);

  std::vector<MemoryMap32> maps;

 private:
  Memory32(void) = delete;
};

class SystemCall32 {
 public:
  virtual ~SystemCall32(void);

  virtual void SetReturn(int ret_val) const = 0;

  virtual int GetSystemCallNum(void) const = 0;

  inline bool TryGetInt32(int arg_num, int32_t *val) const {
    return TryGetArgValue(arg_num, sizeof(int32_t), val);
  }

  inline bool TryGetUInt32(int arg_num, uint32_t *val) const {
    return TryGetArgValue(arg_num, sizeof(uint32_t), val);
  }

  int32_t GetInt32(int arg_num) const;
  uint32_t GetUInt32(int arg_num) const;

 protected:
  virtual bool TryGetArgValue(
      int arg_num, size_t value_size, void *value) const = 0;

  SystemCall32(void) = default;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_OS_SYSTEM32_H_
