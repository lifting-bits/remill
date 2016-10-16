/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_RUNTIME_STATE_H_
#define REMILL_ARCH_RUNTIME_STATE_H_

struct ArchState final {
 public:

  // Used to communicate the interrupt vector number to an intrinsic. The
  // issue is that the interrupt number is part of an instruction, and our
  // generic three-operand block/intrinsic form (state, mem, pc) doesn't
  // have room to hold a vector number.
  uint32_t interrupt_vector;
  uint32_t _tear0;
} __attribute__((packed));

#endif  // REMILL_ARCH_RUNTIME_STATE_H_
