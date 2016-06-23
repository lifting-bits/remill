/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_X86_REGISTERANALYSIS_H_
#define REMILL_ARCH_X86_REGISTERANALYSIS_H_

// Note: This file is split away so that `remill/Arch/Arch.cpp` doesn't need
//       to bring in all of XED.

#include "remill/Arch/X86/AutoAnalysis.h"
#include "remill/Arch/X86/XED.h"

namespace remill {
namespace x86 {

// Flow type for function analysis.
enum FlowType {
  kFlowUnknown,
  kFlowReturn,
  kFlowSysCall,
  kFlowIndirectCall,
  kFlowCall,
  kFlowLocal
};

union RegisterSet {
  struct {
    uint16_t rax:1;
    uint16_t rcx:1;
    uint16_t rdx:1;
    uint16_t rbx:1;
    uint16_t rsp:1;
    uint16_t rbp:1;
    uint16_t rsi:1;
    uint16_t rdi:1;
    uint16_t r8:1;
    uint16_t r9:1;
    uint16_t r10:1;
    uint16_t r11:1;
    uint16_t r12:1;
    uint16_t r13:1;
    uint16_t r14:1;
    uint16_t r15:1;
  } __attribute((packed)) s;
  uint16_t flat;
} __attribute__((packed));

struct BasicBlockRegs {
  uint64_t address;
  FlowType flow;

  struct {
    // Flags that are live anywhere in this block.
    xed_flag_set_t live_anywhere;

    // Flags that are live on entry, after factoring in those flags that are
    // live from the successors.
    xed_flag_set_t live_entry;

    // Minimal set of flags that must be kept alive.
    //
    // When our analysis is done, we will change this to `live_exit` so that
    // when we're lifting code, we can update this as each instruction
    // revives/kills flags and inject the corresponding kills.
    xed_flag_set_t revive;
    xed_flag_set_t kill;

    // Lift flags from all successors.
    xed_flag_set_t live_exit;
  } flags;

  struct {
    RegisterSet live_entry;
    RegisterSet live_exit;
    RegisterSet revive;
    RegisterSet kill;
  } regs;

  // Addresses of successor blocks. Empty if there are none or an unknown
  // number.
  std::vector<uint64_t> predecessors;
  std::vector<uint64_t> successors;

  void UpdateEntryLive(const xed_decoded_inst_t *instr);
};

}  // namespace x86
}  // namespace remill

#endif  // REMILL_ARCH_X86_REGISTERANALYSIS_H_
