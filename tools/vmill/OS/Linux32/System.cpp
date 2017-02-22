/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <cerrno>
#include <iostream>
#include <limits>
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
    : Process(snapshot_, main_thread_),
      memory(memory_) {}

// Create a process from a snapshot.
Process *Process32::Create(const Snapshot *snapshot) {
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

// Return a function that can be used to try to read executable bytes from
// a process's memory.
ByteReaderCallback Process32::ExecutableByteReader(void) {
  return [=] (Addr64 addr, uint8_t *bytes) {

    // TODO(pag): Check memory access permissions.
    return TryReadByte(static_cast<uintptr_t>(addr), bytes);
  };
}

namespace {

static inline bool CheckInBounds(uintptr_t addr, size_t num_bytes) {
  auto max_addr = static_cast<uintptr_t>(std::numeric_limits<Addr32>::max());
  return (addr + num_bytes) < max_addr;
}

}  // namespace

bool Process32::TryReadBytes(uintptr_t addr, void *val,
                             size_t num_bytes) const {
  if (!CheckInBounds(addr, num_bytes)) {
    return false;
  }

  // TODO(pag): Handle faults.
  memcpy(val, memory->UnsafeBytePtr(static_cast<Addr32>(addr)), num_bytes);
  return true;
}

bool Process32::TryWriteBytes(uintptr_t addr, const void *val,
                              size_t num_bytes) const {
  if (!CheckInBounds(addr, num_bytes)) {
    return false;
  }

  // TODO(pag): Handle faults.
  memcpy(memory->UnsafeBytePtr(static_cast<Addr32>(addr)), val, num_bytes);
  return true;
}

// Return the machine state to be executed.
void *Process32::MachineState(void) {
  return CurrentThread()->MachineState();
}

void *Process32::Memory(void) {
  return memory;
}

// Process an asynchronous hypercall for the thread `thread`.
//
// TODO(pag): I don't particularly like this setup, especially not the cast
//            below. This has come through some API refactorings, and some
//            more are needed to really flesh out the structure of processes
//            and how they interact with the executor. In some sense, the
//            executor should have a lot to do with the handling of hypercalls.
void Process32::HandleAsyncHyperCall(Thread *thread_) {
  Process::gCurrent = this;
  auto thread = reinterpret_cast<Thread32 *>(thread_);
  auto pc = thread->NextProgramCounter();
  switch (auto hypercall = thread->PendingHyperCall()) {
    case AsyncHyperCall::kX86SysCall:
    case AsyncHyperCall::kX86SysEnter:
    case AsyncHyperCall::kX86IntN:
      thread->DoSystemCall(
          hypercall, std::bind(
              &Process32::DoSystemCall, this, std::placeholders::_1));
      break;

    case AsyncHyperCall::kInvalid:
      LOG(FATAL)
          << "Executing invalid asynchronous hyper call at " << std::hex << pc;
      Kill();
      break;

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

    case AsyncHyperCall::kInvalidInstruction:
      LOG(FATAL)
          << "Executing invalid instruction at " << std::hex << pc;
      Kill();
      break;
  }
  Process::gCurrent = nullptr;
}


Thread32::~Thread32(void) {}

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
    bool can_read = false;
    bool can_write = false;
    bool can_exec = false;

    switch (page_info.perms) {
      case PagePerms::kInvalid:
        break;
      case PagePerms::kWriteOnly:
        prot = PROT_WRITE;
        can_write = true;
        break;
      case PagePerms::kReadOnly:
        prot = PROT_READ;
        can_read = true;
        can_exec = false;
        break;
      case PagePerms::kReadExec:
        prot = PROT_READ;
        can_read = true;
        can_exec = true;
        break;
      case PagePerms::kReadWrite:
      case PagePerms::kReadWriteExec:
        prot = PROT_READ | PROT_WRITE;
        can_read = true;
        can_write = true;
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
        can_read,
        can_write,
        can_exec,
        0};

    map.can_read = map.is_read;
    map.can_write = map.is_write && !map.is_exec;
    map.can_exec = map.is_exec;
    maps.push_back(map);

    DLOG(INFO)
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
