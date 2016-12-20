/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <cerrno>
#include <iostream>
#include <sys/mman.h>

#include "remill/Arch/Name.h"

#include "tools/vmill/OS/Linux32/System.h"

#include "tools/vmill/Arch/X86/Linux32.h"
#include "tools/vmill/Snapshot/File.h"
#include "tools/vmill/Snapshot/Snapshot.h"

namespace remill {
namespace vmill {

enum : size_t {
  k1MiB = 1ULL << 20ULL,
  k1GiB = 1ULL << 30ULL,
  k4GiB = k1GiB * 4ULL,
};

Process32::~Process32(void) {
  Kill();
  delete memory;
}

Process32::Process32(const Snapshot *snapshot_, Memory32 *memory_,
                     Thread32 *main_thread_)
    : Process(),
      memory(memory_),
      snapshot(snapshot_),
      threads{main_thread_} {
  (void) snapshot;
}

// Create a process from a snapshot.
Process32 *Process32::Create(const Snapshot *snapshot) {
  auto memory = Memory32::Create(snapshot);
  if (!memory) {
    return nullptr;
  }

  auto thread = Thread32::Create(snapshot);
  if (!thread) {
    delete memory;
    return nullptr;
  }

  return new Process32(snapshot, memory, thread);
}

CodeVersion Process32::CodeVersion(void) {
  return 0;  // TODO(pag): Implement me!
}

// Kill this process; this destroys its current threads.
void Process32::Kill(void) {
  for (auto &thread : threads) {
    delete thread;
  }
  threads.clear();
}

// Currently execution thread;
Thread32 *Process32::CurrentThread(void) const {
  if (threads.size()) {
    return threads[0];
  } else {
    return nullptr;
  }
}

// Schedule the next runnable thread, and return it.
Thread32 *Process32::ScheduleNextThread(void) {
  if (threads.size()) {
    return threads[0];
  } else {
    return nullptr;
  }
}

// Return a function that can be used to try to read executable bytes from
// a process's memory.
ByteReaderCallback Process32::ExecutableByteReader(void) {
  return [=] (Addr64 addr, uint8_t *bytes) {
    *bytes = *memory->UnsafeBytePtr(addr);
    return true;  // TODO(pag): Handle fault recovery.
  };
}

// Return the next program counter of code to execute.
uint64_t Process32::ProgramCounter(void) {
  return CurrentThread()->ProgramCounter();
}


// Return the machine state to be executed.
void *Process32::MachineState(void) {
  return CurrentThread()->MachineState();
}

void *Process32::Memory(void) {
  return memory;
}

// Read data from the emulated process.
bool Process32::TryReadByte(Addr32 addr, uint8_t *byte_val) const {
  *byte_val = *memory->UnsafeBytePtr(addr);
  return true;
}

bool Process32::TryReadWord(Addr32 addr, uint16_t *word_val) const {
  *word_val = *memory->UnsafeWordPtr(addr);
  return true;
}

bool Process32::TryReadDword(Addr32 addr, uint32_t *dword_val) const {
  *dword_val = *memory->UnsafeDwordPtr(addr);
  return true;
}

bool Process32::TryReadQword(Addr32 addr, uint64_t *qword_val) const {
  *qword_val = *memory->UnsafeQwordPtr(addr);
  return true;
}

// Write data to the emulated process.
bool Process32::TryWriteByte(Addr32 addr, uint8_t byte_val) const {
  *memory->UnsafeBytePtr(addr) = byte_val;
  return true;
}

bool Process32::TryWriteWord(Addr32 addr, uint16_t word_val) const {
  *memory->UnsafeWordPtr(addr) = word_val;
  return true;
}

bool Process32::TryWriteDword(Addr32 addr, uint32_t dword_val) const {
  *memory->UnsafeDwordPtr(addr) = dword_val;
  return true;
}

bool Process32::TryWriteQword(Addr32 addr, uint64_t qword_val) const {
  *memory->UnsafeQwordPtr(addr) = qword_val;
  return true;
}

// Process an asynchronous hypercall for the thread `thread`.
void Process32::ProcessAsyncHyperCall(Thread32 *thread) {

  switch (auto hypercall = thread->GetHyperCall()) {
    case AsyncHyperCall::kX86SysCall:
    case AsyncHyperCall::kX86SysEnter:
    case AsyncHyperCall::kX86IntN:
      thread->DoSystemCall(
          hypercall, std::bind(
              &Process32::DoSystemCall, this, std::placeholders::_1));
      break;

    case AsyncHyperCall::kInvalid:

    // Interrupts calls.
    case AsyncHyperCall::kX86Int1:
    case AsyncHyperCall::kX86Int3:
    case AsyncHyperCall::kX86IntO:
      Kill();
      break;
    case AsyncHyperCall::kX86Bound:
    case AsyncHyperCall::kX86IRet:
    case AsyncHyperCall::kX86SysRet:
    case AsyncHyperCall::kX86SysExit:
      Kill();
      break;
  }
}


Thread32::~Thread32(void) {}

Thread32::Thread32(pid_t pid_, pid_t tid_)
    : pid(pid_),
      tid(tid_) {}

Thread32 *Thread32::Create(const Snapshot *snapshot) {
  switch (snapshot->GetArch()) {
    case kArchX86:
    case kArchX86_AVX:
    case kArchX86_AVX512:
      return x86::CreateThread32(snapshot);

    case kArchAMD64:
    case kArchAMD64_AVX:
    case kArchAMD64_AVX512:
      LOG(FATAL)
          << "Cannot create an amd64 thread object (yet)";
      return nullptr;

    default:
      LOG(FATAL)
          << "Cannot create an a thread object for an unknown architecture.";
      return nullptr;
  }
}

Memory32 *Memory32::Create(const Snapshot *snapshot) {
  snapshot->ValidatePageInfo(k4GiB);

  std::vector<MemoryMap32> maps;
  maps.reserve(SnapshotFile::kMaxNumPageInfos + 1);
  maps.push_back({0, 4096, 0, 0, 0, 0, 0, 0, 0});  // Zero page.

  for (const auto &page_info : snapshot->file->pages) {
    if (PagePerms::kInvalid == page_info.perms) {
      break;
    }

    uint64_t prot = PROT_NONE;

    switch (page_info.perms) {
      case PagePerms::kInvalid:
        break;
      case PagePerms::kWriteOnly:
        prot = PROT_WRITE;
        break;
      case PagePerms::kReadOnly:
      case PagePerms::kReadExec:
      case PagePerms::kReadWriteExec:
        prot = PROT_READ;
        break;
      case PagePerms::kReadWrite:
        prot = PROT_READ | PROT_WRITE;
        break;
    }

    auto flags = MAP_PRIVATE | MAP_FILE | MAP_FIXED | MAP_NORESERVE | MAP_32BIT;
    auto range_addr = reinterpret_cast<void *>(page_info.base_address);
    auto range_size = page_info.limit_address - page_info.base_address;
    auto mapped_addr = mmap64(
        range_addr, range_size, prot, flags, snapshot->fd,
        static_cast<off64_t>(page_info.offset_in_file));

    CHECK(range_addr == mapped_addr)
        << "Unable to map snapshotted memory from " << snapshot->path
        << " into the right place: " << strerror(errno);

    auto perms = page_info.perms;
    MemoryMap32 map = {
        static_cast<uint32_t>(page_info.base_address),
        static_cast<uint32_t>(page_info.limit_address),
        PagePerms::kWriteOnly != perms,
        PagePerms::kReadOnly != perms,
        PagePerms::kReadExec == perms || PagePerms::kReadWriteExec == perms,
        0,
        0,
        0,
        0};

    map.can_read = map.is_read;
    map.can_write = map.is_write && !map.is_exec;
    map.can_exec = map.is_exec;
    maps.push_back(map);

    LOG(INFO)
        << "Adding page [" << std::hex << map.base_address << ", "
        << std::hex << map.limit_address << ") with permissions "
        << ("-r")[map.is_read] << ("-w")[map.is_write] << ("-x")[map.is_exec]
        << " and available actions " << ("-r")[map.can_read]
        << ("-w")[map.can_write] << ("-x")[map.can_exec];
  }

  return new Memory32(maps);
}

Memory32::Memory32(const std::vector<MemoryMap32> &maps_)
    : maps(maps_) {}

Memory32::~Memory32(void) {
  CHECK(!munmap(reinterpret_cast<void *>(4096 * 16), k4GiB - (4096 * 16)))
      << "Could not free 32-bit address space: " << strerror(errno);
}

SystemCall32::~SystemCall32(void) {}

int32_t SystemCall32::GetInt32(int arg_num) const {
  int32_t val = 0;
  CHECK(TryGetInt32(arg_num, &val))
      << "Unable to read 32-bit integer system call argument " << arg_num;
  return val;
}

uint32_t SystemCall32::GetUInt32(int arg_num) const {
  uint32_t val = 0;
  CHECK(TryGetUInt32(arg_num, &val))
      << "Unable to read 32-bit unsigned integer system call argument "
      << arg_num;
  return val;
}

}  // namespace vmill
}  // namespace remill
