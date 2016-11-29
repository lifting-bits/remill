/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_RUNTIME_HYPERCALL_H_
#define REMILL_ARCH_RUNTIME_HYPERCALL_H_

enum class SyncHyperCall : uint32_t {
  kInvalid,
  kX86CPUID,
  kX86ReadTSC,
  kX86ReadTSCP,

  kX86EmulateInstruction,
  kAMD64EmulateInstruction
};

enum class AsynchHyperCall : uint32_t {
  kInvalid,

  // Interrupts calls.
  kX86Int1,
  kX86Int3,
  kX86IntO,
  kX86IntN,
  kX86Bound,

  // Interrupt returns.
  kX86IRet,

  // System calls.
  kX86SysCall,
  kX86SysRet,

  kX86SysEnter,
  kX86SysExit,
};

#endif  // REMILL_ARCH_RUNTIME_HYPERCALL_H_
