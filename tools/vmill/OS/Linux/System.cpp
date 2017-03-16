/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */


#include <glog/logging.h>

#include <cerrno>
#include <iostream>
#include <limits>
#include <sys/mman.h>

#include "remill/Arch/Name.h"

#include "tools/vmill/Arch/X86/Linux32.h"
#include "tools/vmill/OS/Linux/System.h"
#include "tools/vmill/Snapshot/File.h"
#include "tools/vmill/Snapshot/Snapshot.h"

namespace remill {
namespace vmill {

enum : size_t {
  k1MiB = 1ULL << 20ULL,
  k1GiB = 1ULL << 30ULL,
  k4GiB = k1GiB * 4ULL,
};

LinuxProcess::~LinuxProcess(void) {
  Kill();
  delete memory;
}

LinuxProcess::LinuxProcess(const Snapshot *snapshot_, LinuxMemory *memory_,
                           LinuxThread *main_thread_)
    : Process(snapshot_, main_thread_),
      memory(memory_) {}

// Create a process from a snapshot.
Process *LinuxProcess::Create(const Snapshot *snapshot) {
  auto memory = LinuxMemory::Create(snapshot);
  if (!memory) {
    return nullptr;
  }

  auto thread = LinuxThread::Create(snapshot);
  if (!thread) {
    delete memory;
    return nullptr;
  }

  return new LinuxProcess(snapshot, memory, thread);
}

// Process an asynchronous hypercall for the thread `thread`.
//
// TODO(pag): I don't particularly like this setup, especially not the cast
//            below. This has come through some API refactorings, and some
//            more are needed to really flesh out the structure of processes
//            and how they interact with the executor. In some sense, the
//            executor should have a lot to do with the handling of hypercalls.
void LinuxProcess::HandleAsyncHyperCall(Thread *thread_) {
  auto thread = reinterpret_cast<LinuxThread *>(thread_);
  auto pc = thread->NextProgramCounter();
  auto state = thread->MachineState();
  switch (state->hyper_call) {
    case AsyncHyperCall::kX86SysCall:
    case AsyncHyperCall::kX86SysEnter:
    case AsyncHyperCall::kX86IntN:
      thread->DoSystemCall(
          state->hyper_call, std::bind(
              &LinuxProcess::DoSystemCall, this, std::placeholders::_1));
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
}

LinuxThread::~LinuxThread(void) {}

std::unique_ptr<Thread> LinuxThread::Create(const Snapshot *snapshot) {
  switch (snapshot->GetArch()) {
    case kArchX86:
    case kArchX86_AVX:
    case kArchX86_AVX512:
      return Create32(snapshot);

    default:
      LOG(FATAL)
          << "Cannot create Linux thread for a non-32-bit x86 architecture.";
      return nullptr;
  }
}

LinuxMemory *LinuxMemory::Create(const Snapshot *snapshot) {
  snapshot->ValidatePageInfo(k4GiB);

  std::vector<AddressRange> maps;
  maps.reserve(SnapshotFile::kMaxNumPageInfos);

  for (const auto &page_info : snapshot->file->pages) {
    if (PagePerms::kInvalid == page_info.perms) {
      continue;
    }

    AddressRange map = {};
    map.base_address = static_cast<uint32_t>(page_info.base_address);
    map.limit_address = static_cast<uint32_t>(page_info.limit_address);

    uint64_t prot = PROT_NONE;
    switch (page_info.perms) {
      case PagePerms::kInvalid:
        break;
      case PagePerms::kWriteOnly:
        prot = PROT_WRITE;
        map.is_write = true;
        break;
      case PagePerms::kReadOnly:
        prot = PROT_READ;
        map.can_read = true;
        break;
      case PagePerms::kReadExec:
        prot = PROT_READ;
        map.can_read = true;
        map.can_exec = true;
        break;
      case PagePerms::kReadWrite:
        prot = PROT_READ | PROT_WRITE;
        map.can_read = true;
        map.is_write = true;
        break;
      case PagePerms::kReadWriteExec:
        prot = PROT_READ | PROT_WRITE;
        map.can_read = true;
        map.is_write = true;
        map.can_exec = true;
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

    maps.push_back(map);

    DLOG(INFO)
        << "Adding page [" << std::hex << map.base_address << ", "
        << std::hex << map.limit_address << ") with permissions "
        << ("-r")[map.can_read] << ("-w")[map.is_write] << ("-x")[map.can_exec];
  }

  return new LinuxMemory(maps);
}

LinuxMemory::LinuxMemory(const std::vector<AddressRange> &maps_)
    : maps(maps_) {}

LinuxMemory::~LinuxMemory(void) {
  CHECK(!munmap(reinterpret_cast<void *>(4096 * 16), k4GiB - (4096 * 16)))
      << "Could not free 32-bit address space: " << strerror(errno);
}

namespace {

static inline bool CheckInBounds(uintptr_t addr, size_t num_bytes) {
  return (addr + num_bytes) == static_cast<uint32_t>(addr + num_bytes);
}

}  // namespace


bool LinuxMemory::TryReadBytes(uint64_t addr, void *data, size_t size) const {
  if (!CheckInBounds(addr, size)) {
    return false;
  }

  // TODO(pag): Handle faults.
  memcpy(data, reinterpret_cast<const void *>(addr), size);
  return true;
}

bool LinuxMemory::TryWriteBytes(
    uint64_t addr, const void *data, size_t size) const {
  if (!CheckInBounds(addr, size)) {
    return false;
  }

  // TODO(pag): Handle faults.
  memcpy(reinterpret_cast<void *>(addr), data, size);
  return true;
}

// Query the process's virtual memory map to get information about some
// mapped pages.
const AddressRange *LinuxMemory::QueryMemoryImpl(uint64_t addr) const {
  for (const auto &info : maps) {
    if (info.base_address <= addr && addr < info.limit_address) {
      return &info;
    }
  }
  return nullptr;
}

}  // namespace vmill
}  // namespace remill
