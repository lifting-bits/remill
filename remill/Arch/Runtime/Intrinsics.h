/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_SEMANTICS_INSTRINSICS_H_
#define REMILL_ARCH_SEMANTICS_INSTRINSICS_H_

#include "remill/Arch/Runtime/Types.h"

extern "C" {

// The basic block "template".
[[gnu::used]]
void __remill_basic_block(State &state, Memory &memory, addr_t);

// Address computation intrinsic. This is only used for non-zero
// `address_space`d memory accesses.
[[gnu::used, gnu::const]]
extern addr_t __remill_compute_address(
    const State &state, addr_t address, int address_space);

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

//[[gnu::used]]
//extern Memory *__remill_read_memory_f80(Memory *, addr_t, float80_t &);

[[gnu::used, gnu::const]]
extern Memory *__remill_write_memory_f32(Memory *, addr_t, float32_t);

[[gnu::used, gnu::const]]
extern Memory *__remill_write_memory_f64(Memory *, addr_t, float64_t);

//[[gnu::used]]
//extern Memory *__remill_write_memory_f80(Memory *, addr_t, const float80_t &);

[[gnu::used, gnu::const]]
extern bool __remill_undefined_bool(void);

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
extern void __remill_error(State &, Memory *, addr_t addr);

// Control-flow intrinsics.
[[gnu::used]]
extern void __remill_function_call(State &, Memory *, addr_t addr);

[[gnu::used]]
extern void __remill_function_return(State &, Memory *, addr_t addr);

[[gnu::used]]
extern void __remill_jump(State &, Memory *, addr_t addr);

[[gnu::used]]
extern void __remill_system_call(State &, Memory *, addr_t ret_addr);

[[gnu::used]]
extern void __remill_system_return(State &, Memory *, addr_t addr);

[[gnu::used]]
extern void __remill_interrupt_call(State &, Memory *, addr_t ret_addr);

[[gnu::used]]
extern void __remill_interrupt_return(State &, Memory *, addr_t);

// Represents a known unknown block.
[[gnu::used]]
extern void __remill_missing_block(State &, Memory *, addr_t);

//[[gnu::used]]
//extern bool __remill_conditional_branch(
//    bool condition, addr_t if_true, addr_t if_false);

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

// Arch-specific feature lookup. Implemented as a pseudo control-flow
// intrinsic.
[[gnu::used]]
extern void __remill_read_cpu_features(State &, Memory *, addr_t addr);

// "Fake" intrinsics, implemented in terms of other intrinsics. Why use these
// fake intrinsics? When we go to bitcode, we don't want LLVM to introduce
// struct returns (i.e. passing a pointer to the function that will act
// as the destination of the return value). We don't really want that because
// it means that some of the intrinsics will be non-uniform, and special
// cases are annoying.
[[gnu::used, gnu::const]]
uint128_t __remill_read_memory_128(Memory *, addr_t);


[[gnu::used, gnu::const]]
Memory *__remill_write_memory_128(Memory *, addr_t, uint128_t);

//// Arch-specific. Marshal a float80_t into a float64_t.
////
//// TODO(pag): https://stackoverflow.com/questions/2963055/msvc-win32-convert-extended-precision-float-80-bit-to-double-64-bit
//extern float64_t __remill_read_f80(const float80_t &);
//
//// Arch-specific. Marshal a float64_t into a float64_t.
//extern void __remill_write_f80(const float64_t, float80_t &);

#define __remill_barrier_compiler()
//  __asm__ __volatile__ ("" ::: "memory")

[[gnu::used]]
extern void __remill_intrinsics(void);

}  // extern C

#endif  // REMILL_ARCH_SEMANTICS_INSTRINSICS_H_
