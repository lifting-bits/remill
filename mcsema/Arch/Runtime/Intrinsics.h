/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_SEMANTICS_INSTRINSICS_H_
#define MCSEMA_ARCH_SEMANTICS_INSTRINSICS_H_

#include "mcsema/Arch/Runtime/Types.h"

extern "C" {

extern order_t __mcsema_memory_order;

// The basic block "template".
[[gnu::used]] void __mcsema_basic_block(State &state, addr_t);

// Address computation intrinsic. This is only used for non-zero
// `address_space`d memory accesses.
[[gnu::used]] extern addr_t __mcsema_compute_address(const State &state,
                                                     addr_t address,
                                                     int address_space);

// Semantics, describes that some value is now a possible program counter.
[[gnu::used]] extern addr_t __mcsema_create_program_counter(addr_t);

// Memory read intrinsics.
[[gnu::used]] extern uint8_t __mcsema_read_memory_8(order_t, addr_t);
[[gnu::used]] extern uint16_t __mcsema_read_memory_16(order_t, addr_t);
[[gnu::used]] extern uint32_t __mcsema_read_memory_32(order_t, addr_t);
[[gnu::used]] extern uint64_t __mcsema_read_memory_64(order_t, addr_t);

[[gnu::used]] extern vec8_t __mcsema_read_memory_v8(order_t, addr_t);
[[gnu::used]] extern vec16_t __mcsema_read_memory_v16(order_t, addr_t);
[[gnu::used]] extern vec32_t __mcsema_read_memory_v32(order_t, addr_t);
[[gnu::used]] extern vec64_t __mcsema_read_memory_v64(order_t, addr_t);
[[gnu::used]] extern vec128_t __mcsema_read_memory_v128(order_t, addr_t);
[[gnu::used]] extern vec256_t __mcsema_read_memory_v256(order_t, addr_t);
[[gnu::used]] extern vec512_t __mcsema_read_memory_v512(order_t, addr_t);

// Memory write intrinsics.
[[gnu::used]] extern order_t __mcsema_write_memory_8(order_t, addr_t, uint8_t);
[[gnu::used]] extern order_t __mcsema_write_memory_16(order_t, addr_t, uint16_t);
[[gnu::used]] extern order_t __mcsema_write_memory_32(order_t, addr_t, uint32_t);
[[gnu::used]] extern order_t __mcsema_write_memory_64(order_t, addr_t, uint64_t);

[[gnu::used]] extern order_t __mcsema_write_memory_v8(order_t, addr_t, vec8_t);
[[gnu::used]] extern order_t __mcsema_write_memory_v16(order_t, addr_t, vec16_t);
[[gnu::used]] extern order_t __mcsema_write_memory_v32(order_t, addr_t, vec32_t);
[[gnu::used]] extern order_t __mcsema_write_memory_v64(order_t, addr_t, vec64_t);
[[gnu::used]] extern order_t __mcsema_write_memory_v128(order_t, addr_t, vec128_t);
[[gnu::used]] extern order_t __mcsema_write_memory_v256(order_t, addr_t, vec256_t);
[[gnu::used]] extern order_t __mcsema_write_memory_v512(order_t, addr_t, vec512_t);

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
[[gnu::used]] extern void __mcsema_error(State &, addr_t addr);

// Control-flow intrinsics.
[[gnu::used]] extern void __mcsema_function_call(State &, addr_t addr);
[[gnu::used]] extern void __mcsema_function_return(State &, addr_t addr);
[[gnu::used]] extern void __mcsema_jump(State &, addr_t addr);
[[gnu::used]] extern void __mcsema_system_call(State &, addr_t ret_addr);
[[gnu::used]] extern void __mcsema_system_return(State &, addr_t addr);
[[gnu::used]] extern void __mcsema_interrupt_call(State &, addr_t ret_addr);
[[gnu::used]] extern void __mcsema_interrupt_return(State &, addr_t addr);

// Represents a known unknown block.
[[gnu::used]] extern void __mcsema_missing_block(State &, addr_t);

[[gnu::used]] extern addr_t __mcsema_conditional_branch(
    bool condition, addr_t if_true, addr_t if_false);

// Memory barriers types, see: http://g.oswego.edu/dl/jmm/cookbook.html
[[gnu::used]] extern order_t __mcsema_barrier_load_load(order_t);
[[gnu::used]] extern order_t __mcsema_barrier_load_store(order_t);
[[gnu::used]] extern order_t __mcsema_barrier_store_load(order_t);
[[gnu::used]] extern order_t __mcsema_barrier_store_store(order_t);

// Atomic operations. The address/size are hints, but the granularity of the
// access can be bigger. These have implicit StoreLoad semantics.
[[gnu::used]] extern order_t __mcsema_atomic_begin(order_t);
[[gnu::used]] extern order_t __mcsema_atomic_end(order_t);

#define __mcsema_barrier_compiler()

//  __asm__ __volatile__ ("" ::: "memory")

}  // extern C

[[gnu::used]] extern void __mcsema_intrinsics(void);

#endif  // MCSEMA_ARCH_SEMANTICS_INSTRINSICS_H_
