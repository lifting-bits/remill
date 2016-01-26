/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_CGC_PROCESS_H_
#define TOOLS_CGC_PROCESS_H_

#define ADDRESS_WIDTH_BITS 32
#define HAS_FEATURE_AVX 0
#define HAS_FEATURE_AVX512 0

#include <unordered_map>

#include "mcsema/Arch/X86/Runtime/State.h"

namespace cgc {

typedef void (LiftedBlock)(State &);

struct Process final {
  Process *next;
  bool is_running;
  void *code;
  uintptr_t base;
  uintptr_t limit;
  std::unordered_map<addr_t, LiftedBlock *> blocks;

  State *state;

  void Execute(void);
  LiftedBlock *Find(addr_t addr);
};

Process *CreateProcesses(int num_processes);

} // namespace cgc

#endif  // TOOLS_CGC_PROCESS_H_
