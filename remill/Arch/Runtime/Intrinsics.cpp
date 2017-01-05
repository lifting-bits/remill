/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_SEMANTICS_INSTRINSICS_CPP_
#define REMILL_ARCH_SEMANTICS_INSTRINSICS_CPP_

#include "remill/Arch/Runtime/Intrinsics.h"
#include "remill/Arch/Runtime/Operators.h"

// List of basic blocks that can be externally referenced.
//
// Note:  This should be a superset of `__remill_exported_blocks` insofar as
//        every `lifted_func` in an `IndirectBlock` should match up with a
//        `lifted_func` in an `ExportedBlock`.
//
// Note:  This will be represented by a `llvm::ConstantAggregateZero` before
//        any blocks are lifted. Each time a CFG is lifted, the translator will
//        rebuild this table.
extern "C" const IndirectBlock __remill_indirect_blocks[1] = {};

// List of names for exported blocks.
extern "C" const NamedBlock __remill_exported_blocks[1] = {};

// List of names for imported blocks.
extern "C" const NamedBlock __remill_imported_blocks[1] = {};

#define USED(sym) \
  __remill_mark_as_used(reinterpret_cast<const void *>(&sym))

// This is two big hacks:
//    1)  This makes sure that a symbol is treated as used and prevents it
//        from being optimized away.
//    2)  This makes sure that some functions are marked has having their
//        addresses taken, and so this prevents dead argument elimination.
extern "C" void __remill_mark_as_used(const void *);

extern "C" void __remill_basic_block(Memory &, State &, addr_t);

// This is just a hack to make sure all these functions appear in the bitcode
// file!
[[gnu::used]]
extern "C" void __remill_intrinsics(void) {

  USED(__remill_basic_block);

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
  USED(__remill_read_memory_f80);

  USED(__remill_write_memory_f32);
  USED(__remill_write_memory_f64);
  USED(__remill_write_memory_f80);

  USED(__remill_barrier_load_load);
  USED(__remill_barrier_load_store);
  USED(__remill_barrier_store_load);
  USED(__remill_barrier_store_store);

  USED(__remill_atomic_begin);
  USED(__remill_atomic_end);

  USED(__remill_defer_inlining);

  USED(__remill_error);

  USED(__remill_function_call);
  USED(__remill_function_return);
  USED(__remill_jump);

  USED(__remill_async_hyper_call);
  USED(__remill_sync_hyper_call);

  USED(__remill_undefined_8);
  USED(__remill_undefined_16);
  USED(__remill_undefined_32);
  USED(__remill_undefined_64);
  USED(__remill_undefined_f32);
  USED(__remill_undefined_f64);
}

#endif  // REMILL_ARCH_SEMANTICS_INSTRINSICS_CPP_
