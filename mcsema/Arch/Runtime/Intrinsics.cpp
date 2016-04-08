/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_SEMANTICS_INSTRINSICS_CPP_
#define MCSEMA_ARCH_SEMANTICS_INSTRINSICS_CPP_

#include "mcsema/Arch/Runtime/Intrinsics.h"

#define USED(sym) \
  __mcsema_mark_as_used(reinterpret_cast<void *>(&sym))

extern "C" order_t __mcsema_memory_order = 0;

// This is two big hacks:
//    1)  This makes sure that a symbol is treated as used and prevents it
//        from being optimized away.
//    2)  This makes sure that some functions are marked has having their
//        addresses taken, and so this prevents dead argument elimination.
extern "C" void __mcsema_mark_as_used(void *);

// This is just a hack to make sure all these functions appear in the bitcode
// file!
[[gnu::used]]
void __mcsema_intrinsics(void) {
  USED(__mcsema_create_program_counter);

  USED(__mcsema_read_memory_8);
  USED(__mcsema_read_memory_16);
  USED(__mcsema_read_memory_32);
  USED(__mcsema_read_memory_64);

  USED(__mcsema_read_memory_v8);
  USED(__mcsema_read_memory_v16);
  USED(__mcsema_read_memory_v32);
  USED(__mcsema_read_memory_v64);
  USED(__mcsema_read_memory_v128);
  USED(__mcsema_read_memory_v256);
  USED(__mcsema_read_memory_v512);

  USED(__mcsema_write_memory_8);
  USED(__mcsema_write_memory_16);
  USED(__mcsema_write_memory_32);
  USED(__mcsema_write_memory_64);

  USED(__mcsema_write_memory_v8);
  USED(__mcsema_write_memory_v16);
  USED(__mcsema_write_memory_v32);
  USED(__mcsema_write_memory_v64);
  USED(__mcsema_write_memory_v128);
  USED(__mcsema_write_memory_v256);
  USED(__mcsema_write_memory_v512);

  USED(__mcsema_read_memory_f32);
  USED(__mcsema_read_memory_f64);
  USED(__mcsema_read_memory_f80);

  USED(__mcsema_write_memory_f32);
  USED(__mcsema_write_memory_f64);
  USED(__mcsema_write_memory_f80);

  USED(__mcsema_barrier_load_load);
  USED(__mcsema_barrier_load_store);
  USED(__mcsema_barrier_store_load);
  USED(__mcsema_barrier_store_store);

  USED(__mcsema_atomic_begin);
  USED(__mcsema_atomic_end);

  USED(__mcsema_compute_address);  // Used for segmented addresses.

  USED(__mcsema_defer_inlining);

  USED(__mcsema_error);

  USED(__mcsema_function_call);
  USED(__mcsema_function_return);
  USED(__mcsema_jump);
  USED(__mcsema_system_call);
  USED(__mcsema_system_return);
  USED(__mcsema_interrupt_call);
  USED(__mcsema_interrupt_return);
  USED(__mcsema_conditional_branch);
  USED(__mcsema_missing_block);

  USED(__mcsema_undefined_bool);
  USED(__mcsema_undefined_8);
  USED(__mcsema_undefined_16);
  USED(__mcsema_undefined_32);
  USED(__mcsema_undefined_64);
  USED(__mcsema_undefined_f32);
  USED(__mcsema_undefined_f64);

  USED(__mcsema_read_f80);
  USED(__mcsema_write_f80);

  USED(__mcsema_read_cpu_features);
}

#endif  // MCSEMA_ARCH_SEMANTICS_INSTRINSICS_CPP_
