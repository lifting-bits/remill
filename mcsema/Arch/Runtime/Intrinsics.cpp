/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include "mcsema/Arch/Runtime/Intrinsics.h"

// This is just a hack to make sure all these functions appear in the bitcode
// file!
[[gnu::used]]
void __mcsema_intrinsics(void) {
  (void) __mcsema_read_memory_8;
  (void) __mcsema_read_memory_16;
  (void) __mcsema_read_memory_32;
  (void) __mcsema_read_memory_64;

  (void) __mcsema_read_memory_v8;
  (void) __mcsema_read_memory_v16;
  (void) __mcsema_read_memory_v32;
  (void) __mcsema_read_memory_v64;
  (void) __mcsema_read_memory_v128;
  (void) __mcsema_read_memory_v256;
  (void) __mcsema_read_memory_v512;

  (void) __mcsema_write_memory_8;
  (void) __mcsema_write_memory_16;
  (void) __mcsema_write_memory_32;
  (void) __mcsema_write_memory_64;

  (void) __mcsema_write_memory_v8;
  (void) __mcsema_write_memory_v16;
  (void) __mcsema_write_memory_v32;
  (void) __mcsema_write_memory_v64;
  (void) __mcsema_write_memory_v128;
  (void) __mcsema_write_memory_v256;
  (void) __mcsema_write_memory_v512;

  (void) __mcsema_barrier_load_load;
  (void) __mcsema_barrier_load_store;
  (void) __mcsema_barrier_store_load;
  (void) __mcsema_barrier_store_store;

  (void) __mcsema_atomic_begin;
  (void) __mcsema_atomic_end;

  (void) __mcsema_compute_address;  // Used for segmented addresses.

  (void) __mcsema_defer_inlining;

  (void) __mcsema_error;

  (void) __mcsema_function_call;
  (void) __mcsema_function_return;
  (void) __mcsema_jump;
  (void) __mcsema_system_call;
  (void) __mcsema_system_return;
  (void) __mcsema_interrupt_call;
  (void) __mcsema_interrupt_return;
  (void) __mcsema_undefined_block;

  (void) __mcsema_undefined_bool;
  (void) __mcsema_undefined_8;
  (void) __mcsema_undefined_16;
  (void) __mcsema_undefined_32;
  (void) __mcsema_undefined_64;
}
