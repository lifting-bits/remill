/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_SEMANTICS_INSTRINSICS_H_
#define MCSEMA_ARCH_SEMANTICS_INSTRINSICS_H_

#include "mcsema/Arch/Runtime/Types.h"

extern "C" {

// The basic block "template".
[[gnu::used]] void __mcsema_basic_block(State &state);

// Address computation intrinsic. This is only used for non-zero
// `address_space`d memory accesses.
[[gnu::used]] extern addr_t __mcsema_compute_address(const State &state,
                                                     addr_t address,
                                                     int address_space);

// Memory read intrinsics.
[[gnu::used]] extern uint8_t __mcsema_read_memory_8(addr_t);
[[gnu::used]] extern uint16_t __mcsema_read_memory_16(addr_t);
[[gnu::used]] extern uint32_t __mcsema_read_memory_32(addr_t);
[[gnu::used]] extern uint64_t __mcsema_read_memory_64(addr_t);

[[gnu::used]] extern void __mcsema_read_memory_v8(addr_t, vec8_t &);
[[gnu::used]] extern void __mcsema_read_memory_v16(addr_t, vec16_t &);
[[gnu::used]] extern void __mcsema_read_memory_v32(addr_t, vec32_t &);
[[gnu::used]] extern void __mcsema_read_memory_v64(addr_t, vec64_t &);
[[gnu::used]] extern void __mcsema_read_memory_v128(addr_t, vec128_t &);
[[gnu::used]] extern void __mcsema_read_memory_v256(addr_t, vec256_t &);
[[gnu::used]] extern void __mcsema_read_memory_v512(addr_t, vec512_t &);

// Memory write intrinsics.
[[gnu::used]] extern void __mcsema_write_memory_8(addr_t, uint8_t);
[[gnu::used]] extern void __mcsema_write_memory_16(addr_t, uint16_t);
[[gnu::used]] extern void __mcsema_write_memory_32(addr_t, uint32_t);
[[gnu::used]] extern void __mcsema_write_memory_64(addr_t, uint64_t);

[[gnu::used]] extern void __mcsema_write_memory_v8(addr_t, const vec8_t &);
[[gnu::used]] extern void __mcsema_write_memory_v16(addr_t, const vec16_t &);
[[gnu::used]] extern void __mcsema_write_memory_v32(addr_t, const vec32_t &);
[[gnu::used]] extern void __mcsema_write_memory_v64(addr_t, const vec64_t &);
[[gnu::used]] extern void __mcsema_write_memory_v128(addr_t, const vec128_t &);
[[gnu::used]] extern void __mcsema_write_memory_v256(addr_t, const vec256_t &);
[[gnu::used]] extern void __mcsema_write_memory_v512(addr_t, const vec512_t &);

[[gnu::used]] extern bool __mcsema_undefined_bool(void);
[[gnu::used]] extern uint8_t __mcsema_undefined_8(void);
[[gnu::used]] extern uint16_t __mcsema_undefined_16(void);
[[gnu::used]] extern uint32_t __mcsema_undefined_32(void);
[[gnu::used]] extern uint64_t __mcsema_undefined_64(void);

// Inlining control. The idea here is that sometimes we want to defer inlining
// until a later time, and we need to communicate what should eventually be
// inlined, even if it's not currently inlined.
[[gnu::used]] extern void __mcsema_defer_inlining(void);

// Generic error.
[[gnu::used]] extern void __mcsema_error(State &);

// Control-flow intrinsics.
[[gnu::used]] extern void __mcsema_function_call(State &);
[[gnu::used]] extern void __mcsema_function_return(State &);
[[gnu::used]] extern void __mcsema_jump(State &);
[[gnu::used]] extern void __mcsema_system_call(State &);
[[gnu::used]] extern void __mcsema_system_return(State &);
[[gnu::used]] extern void __mcsema_interrupt_call(State &);
[[gnu::used]] extern void __mcsema_interrupt_return(State &);
[[gnu::used]] extern void __mcsema_undefined_block(State &);

[[gnu::used]] extern addr_t __mcsema_conditional_branch(
    bool condition, addr_t if_true, addr_t if_false);

// Memory barriers types, see: http://g.oswego.edu/dl/jmm/cookbook.html
[[gnu::used]] extern void __mcsema_barrier_load_load(void);
[[gnu::used]] extern void __mcsema_barrier_load_store(void);
[[gnu::used]] extern void __mcsema_barrier_store_load(void);
[[gnu::used]] extern void __mcsema_barrier_store_store(void);

// Atomic operations. The address/size are hints, but the granularity of the
// access can be bigger. These have implicit StoreLoad semantics.
[[gnu::used]] extern void __mcsema_atomic_begin(addr_t, uint32_t);
[[gnu::used]] extern void __mcsema_atomic_end(addr_t, uint32_t);

#define __mcsema_barrier_compiler() \
  __asm__ __volatile__ ("" ::: "memory")

}  // extern C

[[gnu::used]] extern void __mcsema_intrinsics(void);

#endif  // MCSEMA_ARCH_SEMANTICS_INSTRINSICS_H_
