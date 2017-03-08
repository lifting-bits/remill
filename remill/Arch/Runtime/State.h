/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_RUNTIME_STATE_H_
#define REMILL_ARCH_RUNTIME_STATE_H_

#include "remill/Arch/Runtime/HyperCall.h"

struct ArchState {
 public:
  AsyncHyperCall::Name hyper_call;
  uint32_t _0;

  // Used to communicate the interrupt vector number to an intrinsic. The
  // issue is that the interrupt number is part of an instruction, and our
  // generic three-operand block/intrinsic form (state, mem, pc) doesn't
  // have room to hold a vector number.
  uint32_t interrupt_vector;
  uint32_t _1;
} __attribute__((packed));

static_assert(16 == sizeof(ArchState),
              "Invalid packing of `struct ArchState`.");

#endif  // REMILL_ARCH_RUNTIME_STATE_H_
