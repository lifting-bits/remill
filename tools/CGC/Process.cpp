/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <dlfcn.h>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <sstream>
#include <sys/mman.h>

#include "mcsema/Arch/Runtime/Intrinsics.h"

#include "tools/CGC/Process.h"
#include "tools/CGC/Snapshot.h"

DECLARE_string(lifted_dir);

namespace cgc {
namespace {

// Open up a shared library that represents the lifted code from a
// CGC binary.
static void *OpenLiftedCode(int process_id) {
  std::stringstream file_name;
  const char *begin = "";
  if ('/' != FLAGS_lifted_dir[0]) {
    begin = ".";
  }
  file_name << FLAGS_lifted_dir << begin << "/mcsema.lifted." << process_id;
  LOG_IF(FATAL, access(file_name.str().c_str(), R_OK))
    << "Unable to locate lifted code: " << file_name.str();

  dlerror();  // Clear out any errors.

  // Go find the symbol.
  auto code = dlopen(file_name.str().c_str(), RTLD_NOW | RTLD_LOCAL);
  LOG_IF(FATAL, !code)
    << "Unable to load lifted code from " << file_name.str()
    << ": " << dlerror();
  return code;
}

// Allocate a new State structure. These can't be allocated directly because
// they have deleted constructors.
static State *CreateMachineState(void) {
  typedef std::aligned_storage<sizeof(State), alignof(State)>::type T;
  auto state = reinterpret_cast<State *>(new T);
  memset(state, 0, sizeof(State));
  return state;
}

}  // namespace

// Find the address of a lifted block. Once found, cache the address in a
// hash table.
LiftedBlock *Process::Find(addr_t addr) {
  auto &block = blocks[addr];
  if (!block) {
    block = &__mcsema_undefined_block;

    // We have to find the block by its function name, which will be
    // `__lifted_block_<id>_<address>`, where `id` will be `1` (because the
    // code we lifted will be the "first" binary in the bitcode file, and we
    // won't add in more).
    std::stringstream func;
    func << "__lifted_block_1_0x" << std::hex << addr;

    if (auto sym = dlsym(code, func.str().c_str())) {
      block = reinterpret_cast<LiftedBlock *>(sym);
    }
  }
  return block;
}

// Execute some lifted code.
void Process::Execute(void) {
  Find(this->state->gpr.rip.dword)(*state);
}

// Initialize the process data structures. This chains the processes into
// a circularly linked list.
Process *CreateProcesses(int num_processes) {
  Process *first_process = nullptr;
  Process **next_process = nullptr;
  for (auto i = 0; i < num_processes; ++i) {
    auto process = new Process;
    if (next_process) {
      *next_process = process;
    } else {
      next_process = &(process->next);
      first_process = process;
    }

    process->state = CreateMachineState();
    process->code = OpenLiftedCode(i + 1);
    process->is_running = true;
    LoadMemoryFromSnapshot(process, i + 1);
  }
  *next_process = first_process;
  return first_process;
}

}  // namespace cgc
