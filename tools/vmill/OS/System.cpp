/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include "Linux/System.h"

#include <glog/logging.h>

#include "remill/Arch/Name.h"
#include "remill/OS/OS.h"

#include "tools/vmill/OS/System.h"
#include "tools/vmill/OS/Linux/System.h"
#include "tools/vmill/Snapshot/Snapshot.h"

namespace remill {
namespace vmill {

Memory::Memory(void)
    : last_queried_map{} {}

Memory::~Memory(void) {}


Thread::~Thread(void) {}

Thread::Thread(pid_t pid_, pid_t tid_)
    : pid(pid_),
      tid(tid_) {}

std::unique_ptr<Thread> Thread::Create(const Snapshot *snapshot) {
  switch (snapshot->GetOS()) {
    case OSName::kOSLinux:
      return LinuxThread::Create(snapshot);

    default:
      LOG(FATAL)
          << "Cannot create a non-Linux process.";
  }
}

Process::Process(const Snapshot *snapshot_, Thread *main_thread_)
    : snapshot(snapshot_),
      threads{main_thread_} {}

Process::~Process(void) {
  Kill();
}

// Kill this process; this destroys its current threads.
void Process::Kill(void) {
  for (auto &thread : threads) {
    delete thread;
  }
  threads.clear();
}

// Schedule the next runnable thread, and return it.
//
// TODO(pag): Implement this.
Thread *Process::ScheduleNextThread(void) {
  return threads.size() ? threads[0] : nullptr;
}

std::unique_ptr<Process> Process::CreateNativeLinux(const Snapshot *snapshot) {
  switch (snapshot->GetArch()) {
    case kArchInvalid:
      LOG(FATAL)
          << "Cannot create process for an invalid arch.";
      return nullptr;
    case kArchX86:
    case kArchX86_AVX:
    case kArchX86_AVX512:
      return LinuxProcess(snapshot);
    case kArchAMD64:
    case kArchAMD64_AVX:
    case kArchAMD64_AVX512:
      LOG(FATAL)
          << "Cannot emulate 64-bit Linux processes.";
      return nullptr;
  }
}

SystemCallABI::~SystemCallABI(void) {}

int32_t SystemCallABI::GetInt32(int arg_num) const {
  int32_t val = 0;
  CHECK(TryGetInt32(arg_num, &val))
      << "Unable to read 32-bit integer system call argument " << arg_num;
  return val;
}

uint32_t SystemCallABI::GetUInt32(int arg_num) const {
  uint32_t val = 0;
  CHECK(TryGetUInt32(arg_num, &val))
      << "Unable to read 32-bit unsigned integer system call argument "
      << arg_num;
  return val;
}


}  // namespace vmill
}  // namespace remill
