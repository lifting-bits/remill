/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_X86_RUNTIME_OPERATORS_H_
#define REMILL_ARCH_X86_RUNTIME_OPERATORS_H_

namespace {

// Read a register directly. Sometimes this is needed for suppressed operands.
ALWAYS_INLINE static
IF_64BIT_ELSE(uint64_t, uint32_t) _Read(Memory *, Reg reg) {
  return reg.IF_64BIT_ELSE(qword, dword);
}

// Write directly to a register. This is sometimes needed for suppressed
// register operands.
ALWAYS_INLINE static
void _Write(Memory *, Reg &reg, IF_64BIT_ELSE(uint64_t, uint32_t) val) {
  reg.IF_64BIT_ELSE(qword, dword) = val;
}

}  // namespace

#endif  // REMILL_ARCH_X86_RUNTIME_OPERATORS_H_
