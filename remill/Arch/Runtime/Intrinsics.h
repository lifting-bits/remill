/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_RUNTIME_INTRINSICS_H_
#define REMILL_ARCH_RUNTIME_INTRINSICS_H_

#include "remill/Arch/Runtime/Types.h"
#include "remill/Arch/Runtime/HyperCall.h"

struct IndirectBlock final {
  const uint64_t lifted_address;
  void (* const lifted_func)(Memory *, State &, addr_t);
};

// TODO(pag): Add a `lifted_address` field in here for extra cross-checking?
struct NamedBlock final {
  const char * const name;
  void (* const lifted_func)(Memory *, State &, addr_t);
  void (* const native_func)(void);
};

extern "C" {

// The basic block "template".
[[gnu::used]]
void __remill_basic_block(Memory &memory, State &state, addr_t);

// Memory read intrinsics.
[[gnu::used, gnu::const]]
extern uint8_t __remill_read_memory_8(Memory *, addr_t);

[[gnu::used, gnu::const]]
extern uint16_t __remill_read_memory_16(Memory *, addr_t);

[[gnu::used, gnu::const]]
extern uint32_t __remill_read_memory_32(Memory *, addr_t);

[[gnu::used, gnu::const]]
extern uint64_t __remill_read_memory_64(Memory *, addr_t);

// Memory write intrinsics.
[[gnu::used, gnu::const]]
extern Memory *__remill_write_memory_8(Memory *, addr_t, uint8_t);

[[gnu::used, gnu::const]]
extern Memory *__remill_write_memory_16(Memory *, addr_t, uint16_t);

[[gnu::used, gnu::const]]
extern Memory *__remill_write_memory_32(Memory *, addr_t, uint32_t);

[[gnu::used, gnu::const]]
extern Memory *__remill_write_memory_64(Memory *, addr_t, uint64_t);

[[gnu::used, gnu::const]]
extern float32_t __remill_read_memory_f32(Memory *, addr_t);

[[gnu::used, gnu::const]]
extern float64_t __remill_read_memory_f64(Memory *, addr_t);

[[gnu::used]]
extern float64_t __remill_read_memory_f80(Memory *, addr_t);

[[gnu::used, gnu::const]]
extern Memory *__remill_write_memory_f32(Memory *, addr_t, float32_t);

[[gnu::used, gnu::const]]
extern Memory *__remill_write_memory_f64(Memory *, addr_t, float64_t);

[[gnu::used]]
extern Memory *__remill_write_memory_f80(Memory *, addr_t, float64_t);

[[gnu::used, gnu::const]]
extern uint8_t __remill_undefined_8(void);

[[gnu::used, gnu::const]]
extern uint16_t __remill_undefined_16(void);

[[gnu::used, gnu::const]]
extern uint32_t __remill_undefined_32(void);

[[gnu::used, gnu::const]]
extern uint64_t __remill_undefined_64(void);

[[gnu::used, gnu::const]]
extern float32_t __remill_undefined_f32(void);

[[gnu::used, gnu::const]]
extern float64_t __remill_undefined_f64(void);

// Inlining control. The idea here is that sometimes we want to defer inlining
// until a later time, and we need to communicate what should eventually be
// inlined, even if it's not currently inlined.
[[gnu::used]]
extern void __remill_defer_inlining(void);

// Generic error.
[[gnu::used]]
extern void __remill_error(Memory *, State &, addr_t addr);

// Control-flow intrinsics.
[[gnu::used]]
extern void __remill_function_call(Memory *, State &, addr_t addr);

[[gnu::used]]
extern void __remill_function_return(Memory *, State &, addr_t addr);

[[gnu::used]]
extern void __remill_jump(Memory *, State &, addr_t addr);

[[gnu::used]]
extern void __remill_async_hyper_call(Memory *, State &, addr_t ret_addr);

[[gnu::used]]
extern Memory *__remill_sync_hyper_call(Memory *, State &, SyncHyperCall::Name);

// Memory barriers types, see: http://g.oswego.edu/dl/jmm/cookbook.html
[[gnu::used, gnu::const]]
extern Memory *__remill_barrier_load_load(Memory *);

[[gnu::used, gnu::const]]
extern Memory *__remill_barrier_load_store(Memory *);

[[gnu::used, gnu::const]]
extern Memory *__remill_barrier_store_load(Memory *);

[[gnu::used, gnu::const]]
extern Memory *__remill_barrier_store_store(Memory *);

// Atomic operations. The address/size are hints, but the granularity of the
// access can be bigger. These have implicit StoreLoad semantics.
[[gnu::used, gnu::const]]
extern Memory *__remill_atomic_begin(Memory *);

[[gnu::used, gnu::const]]
extern Memory *__remill_atomic_end(Memory *);

}  // extern C

#endif  // REMILL_ARCH_RUNTIME_INTRINSICS_H_
