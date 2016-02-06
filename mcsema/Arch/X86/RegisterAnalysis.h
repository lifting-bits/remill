/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_X86_REGISTERANALYSIS_H_
#define MCSEMA_ARCH_X86_REGISTERANALYSIS_H_

// Note: This file is split away so that `mcsema/Arch/Arch.cpp` doesn't need
//       to bring in all of XED.

#include "mcsema/Arch/X86/AutoAnalysis.h"
#include "mcsema/Arch/X86/XED.h"

namespace mcsema {
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

struct BasicBlockRegs {
  uint64_t address;
  FlowType flow;

  // Flags that are live anywhere in this block.
  xed_flag_set_t live_anywhere;

  // Flags that are live on entry, after factoring in those flags that are
  // live from the successors.
  //
  // When our analysis is done, we will change this to `live_exit` so that when
  // we're lifting code, we can update this as each instruction kills flags
  // and inject the corresponding kills.
  xed_flag_set_t live_entry;

  // Minimal set of flags that must be kept alive.
  xed_flag_set_t keep_alive;

  // Lift flags from all successors.
  xed_flag_set_t live_exit;

  // Addresses of successor blocks. Empty if there are none or an unknown
  // number.
  std::vector<uint64_t> predecessors;
  std::vector<uint64_t> successors;

  void UpdateEntryLive(const xed_decoded_inst_t *instr);
};

}  // namespace x86
}  // namespace mcsema

#endif  // MCSEMA_ARCH_X86_REGISTERANALYSIS_H_
