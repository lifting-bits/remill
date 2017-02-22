/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include "remill/Arch/Name.h"
#include "remill/OS/OS.h"

#include "tools/vmill/OS/System.h"
#include "tools/vmill/OS/Linux32/System.h"
#include "tools/vmill/Snapshot/Snapshot.h"

namespace remill {
namespace vmill {

Thread::~Thread(void) {}

Thread::Thread(pid_t pid_, pid_t tid_)
    : pid(pid_),
      tid(tid_) {}

thread_local Process *Process::gCurrent = nullptr;

// Return the next program counter of code to execute.
uint64_t Process::NextProgramCounter(void) const {
  return CurrentThread()->NextProgramCounter();
}

Process *Process::Create(const Snapshot *snapshot) {
  switch (snapshot->GetOS()) {
    case kOSInvalid:
      LOG(FATAL)
          << "Cannot emulate process for an invalid OS.";
      return nullptr;

    case kOSLinux:
      switch (snapshot->GetArch()) {
        case kArchInvalid:
          LOG(FATAL)
              << "Cannot create process for an invalid arch.";
          return nullptr;
        case kArchX86:
        case kArchX86_AVX:
        case kArchX86_AVX512:
          return Process32::Create(snapshot);
        case kArchAMD64:
        case kArchAMD64_AVX:
        case kArchAMD64_AVX512:
          LOG(FATAL)
              << "Cannot emulate 64-bit Linux processes.";
          return nullptr;
      }

    case kOSmacOS:
      LOG(FATAL)
          << "Cannot emulate a macOS process.";
      return nullptr;
  }
}

Process::Process(const Snapshot *snapshot_, Thread *main_thread_)
    : snapshot(snapshot_),
      threads{main_thread_} {}

// Kill this process; this destroys its current threads.
void Process::Kill(void) {
  for (auto &thread : threads) {
    delete thread;
  }
  threads.clear();
}

// Currently execution thread;
Thread *Process::CurrentThread(void) const {
  if (threads.size()) {
    return threads[0];
  } else {
    return nullptr;
  }
}

// Schedule the next runnable thread, and return it.
Thread *Process::ScheduleNextThread(void) {
  if (threads.size()) {
    return threads[0];
  } else {
    return nullptr;
  }
}

Process::~Process(void) {}

}  // namespace vmill
}  // namespace remill
