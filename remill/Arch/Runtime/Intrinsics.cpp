/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_SEMANTICS_INSTRINSICS_CPP_
#define REMILL_ARCH_SEMANTICS_INSTRINSICS_CPP_

#include "remill/Arch/Runtime/Intrinsics.h"
#include "remill/Arch/Runtime/Operators.h"

#define USED(sym) \
  __remill_mark_as_used(reinterpret_cast<void *>(&sym))

// This is two big hacks:
//    1)  This makes sure that a symbol is treated as used and prevents it
//        from being optimized away.
//    2)  This makes sure that some functions are marked has having their
//        addresses taken, and so this prevents dead argument elimination.
extern "C" void __remill_mark_as_used(void *);

// This is just a hack to make sure all these functions appear in the bitcode
// file!
[[gnu::used]]
 extern "C" void __remill_intrinsics(void) {

  USED(__remill_read_memory_8);
  USED(__remill_read_memory_16);
  USED(__remill_read_memory_32);
  USED(__remill_read_memory_64);

  USED(__remill_write_memory_8);
  USED(__remill_write_memory_16);
  USED(__remill_write_memory_32);
  USED(__remill_write_memory_64);

  USED(__remill_read_memory_f32);
  USED(__remill_read_memory_f64);
//  USED(__remill_read_memory_f80);

  USED(__remill_write_memory_f32);
  USED(__remill_write_memory_f64);
//  USED(__remill_write_memory_f80);

  USED(__remill_barrier_load_load);
  USED(__remill_barrier_load_store);
  USED(__remill_barrier_store_load);
  USED(__remill_barrier_store_store);

  USED(__remill_atomic_begin);
  USED(__remill_atomic_end);

  USED(__remill_compute_address);  // Used for segmented addresses.

  USED(__remill_defer_inlining);

  USED(__remill_error);

  USED(__remill_function_call);
  USED(__remill_function_return);
  USED(__remill_jump);
  USED(__remill_system_call);
  USED(__remill_system_return);
  USED(__remill_interrupt_call);
  USED(__remill_interrupt_return);
//  USED(__remill_conditional_branch);
  USED(__remill_missing_block);

  USED(__remill_undefined_bool);
  USED(__remill_undefined_8);
  USED(__remill_undefined_16);
  USED(__remill_undefined_32);
  USED(__remill_undefined_64);
  USED(__remill_undefined_f32);
  USED(__remill_undefined_f64);

//  USED(__remill_read_f80);
//  USED(__remill_write_f80);

  USED(__remill_read_cpu_features);
}

// TODO(pag): Assumes little-endian.
uint128_t __remill_read_memory_128(Memory *mem, addr_t addr) {
  uint128_t low_qword = ZExt(__remill_read_memory_64(mem, addr));
  uint128_t high_qword = ZExt(__remill_read_memory_64(mem, addr + 8));
  return UOr(UShl(high_qword, 64), low_qword);
}

// TODO(pag): Assumes little-endian.
Memory *__remill_write_memory_128(Memory *mem, addr_t addr, uint128_t val) {
  uint64_t low_qword = Trunc(val);
  uint64_t high_qword = Trunc(UShr(val, 64));
  mem = __remill_write_memory_64(mem, addr, low_qword);
  mem = __remill_write_memory_64(mem, addr + 8, high_qword);
  return mem;
}

#endif  // REMILL_ARCH_SEMANTICS_INSTRINSICS_CPP_
