/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "tools/CGC/Process.h"

DEFINE_string(snapshot_dir, "", "Directory where snapshots are stored.");
DEFINE_string(lifted_dir, "", "Directory where lifted binaries are stored.");
DEFINE_int32(num_exe, 1, "Number of executables to run.");

namespace cgc {
namespace {

// Currently running process.
Process *gProcess = nullptr;

// Schedule the next process.
void Schedule(void) {
  gProcess = gProcess->next;
}

// Run some code from the current process. If the process was running then
// this will return `true`, even if the process hit an error, because it
// still made progress by going from a running to error state.
bool Run(void) {
  auto was_running = gProcess->is_running;
  if (was_running) gProcess->Execute();
  return was_running;
}

// Access memory within the current process.
//
// TODO(pag): Implement a try read/write operations instead of using this.
template <typename T>
ALWAYS_INLINE static T &AccessMemory(addr_t addr) {
  return *reinterpret_cast<T *>(gProcess->base + addr);
}

}  // namespace
}  // namespace cgc

extern "C" {

#define MAKE_RW_MEMORY(size) \
  uint ## size ## _t  __mcsema_read_memory_ ## size(addr_t addr) {\
    return cgc::AccessMemory<uint ## size ## _t>(addr); \
  } \
  void __mcsema_write_memory_ ## size ( \
      addr_t addr, const uint ## size ## _t in) { \
    cgc::AccessMemory<uint ## size ## _t>(addr) = in; \
  }

#define MAKE_RW_VEC_MEMORY(size) \
  void __mcsema_read_memory_v ## size(\
      addr_t addr, vec ## size ## _t &out) { \
    out = cgc::AccessMemory<vec ## size ## _t>(addr); \
  } \
  void __mcsema_write_memory_v ## size (\
      addr_t addr, const vec ## size ## _t &in) { \
    cgc::AccessMemory<vec ## size ## _t>(addr) = in; \
  }

MAKE_RW_MEMORY(8)
MAKE_RW_MEMORY(16)
MAKE_RW_MEMORY(32)
MAKE_RW_MEMORY(64)

MAKE_RW_VEC_MEMORY(8)
MAKE_RW_VEC_MEMORY(16)
MAKE_RW_VEC_MEMORY(32)
MAKE_RW_VEC_MEMORY(64)
MAKE_RW_VEC_MEMORY(128)
MAKE_RW_VEC_MEMORY(256)
MAKE_RW_VEC_MEMORY(512)

// Address computation intrinsic. This is only used for non-zero
// `address_space`d memory accesses.
addr_t __mcsema_compute_address(const State &, addr_t addr, int) {
  LOG(FATAL) << "Computing address of FS- or GS-segmented memory.";
  return addr;
}

void __mcsema_barrier_load_load(void) {}
void __mcsema_barrier_load_store(void) {}
void __mcsema_barrier_store_load(void) {}
void __mcsema_barrier_store_store(void) {}

void __mcsema_atomic_begin(addr_t, uint32_t) {}
void __mcsema_atomic_end(addr_t, uint32_t) {}

void __mcsema_defer_inlining(void) {}

void __mcsema_error(State &state) {
  LOG(ERROR) << "Error: " << std::hex << state.gpr.rip.dword;
  cgc::gProcess->is_running = false;
}

void __mcsema_undefined_block(State &state) {
  LOG(ERROR) << "Undefined block: " << std::hex << state.gpr.rip.dword;
  cgc::gProcess->is_running = false;
}

void __mcsema_function_call(State &) {}
void __mcsema_function_return(State &) {}
void __mcsema_jump(State &) {}

addr_t __mcsema_conditional_branch(bool cond, addr_t addr_true,
                                   addr_t addr_false) {
  return cond ? addr_true : addr_false;
}

void __mcsema_system_call(State &state) {
  LOG(FATAL) << "System call: " << std::hex << state.gpr.rip.dword;
}

void __mcsema_system_return(State &state) {
  LOG(FATAL) << "System return: " << std::hex << state.gpr.rip.dword;
}

void __mcsema_interrupt_call(State &state) {
  LOG(FATAL) << "Interrupt call: " << std::hex << state.gpr.rip.dword;
}

void __mcsema_interrupt_return(State &state) {
  LOG(FATAL) << "Interrupt return: " << std::hex << state.gpr.rip.dword;
}

int main(int argc, char **argv, char **) {
  google::SetUsageMessage(std::string(argv[0]) + " [options]");
  google::ParseCommandLineFlags(&argc, &argv, false);

  LOG_IF(FATAL, 0 >= FLAGS_num_exe)
    << "One or more executables must be available.";

  LOG_IF(FATAL, FLAGS_snapshot_dir.empty())
    << "Must provide a unique path to a directory where the "
    << "snapshots are located persisted.";

  LOG_IF(FATAL, FLAGS_lifted_dir.empty())
    << "Must provide a unique path to a directory where the "
    << "lifted code for each process is located.";

  cgc::gProcess = cgc::CreateProcesses(FLAGS_num_exe);
  for (bool made_progress = true; made_progress; cgc::Schedule()) {
    for (made_progress = false; cgc::Run(); cgc::Schedule()) {
      made_progress = true;
    }
  }

  return EXIT_SUCCESS;
}

}  // extern C
