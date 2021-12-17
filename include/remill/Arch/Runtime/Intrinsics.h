/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "remill/Arch/Runtime/HyperCall.h"
#include "remill/Arch/Runtime/Types.h"

extern "C" {

// Memory read intrinsics.
[[gnu::used, gnu::const]] extern uint8_t __remill_read_memory_8(Memory *,
                                                                addr_t);

[[gnu::used, gnu::const]] extern uint16_t __remill_read_memory_16(Memory *,
                                                                  addr_t);

[[gnu::used, gnu::const]] extern uint32_t __remill_read_memory_32(Memory *,
                                                                  addr_t);

[[gnu::used, gnu::const]] extern uint64_t __remill_read_memory_64(Memory *,
                                                                  addr_t);

// Memory write intrinsics.
[[gnu::used, gnu::const]] extern Memory *
__remill_write_memory_8(Memory *, addr_t, uint8_t);

[[gnu::used, gnu::const]] extern Memory *
__remill_write_memory_16(Memory *, addr_t, uint16_t);

[[gnu::used, gnu::const]] extern Memory *
__remill_write_memory_32(Memory *, addr_t, uint32_t);

[[gnu::used, gnu::const]] extern Memory *
__remill_write_memory_64(Memory *, addr_t, uint64_t);

[[gnu::used, gnu::const]] extern float32_t __remill_read_memory_f32(Memory *,
                                                                    addr_t);

[[gnu::used, gnu::const]] extern float64_t __remill_read_memory_f64(Memory *,
                                                                    addr_t);

[[gnu::used]] extern Memory *__remill_read_memory_f80(Memory *, addr_t,
                                                      native_float80_t &);

[[gnu::used]] extern float128_t __remill_read_memory_f128(Memory *, addr_t);

[[gnu::used, gnu::const]] extern Memory *
__remill_write_memory_f32(Memory *, addr_t, float32_t);

[[gnu::used, gnu::const]] extern Memory *
__remill_write_memory_f64(Memory *, addr_t, float64_t);

[[gnu::used]] extern Memory *
__remill_write_memory_f80(Memory *, addr_t, const native_float80_t &);

[[gnu::used]] extern Memory *__remill_write_memory_f128(Memory *, addr_t,
                                                        float128_t);

[[gnu::used, gnu::const]] extern uint8_t __remill_undefined_8(void);

[[gnu::used, gnu::const]] extern uint16_t __remill_undefined_16(void);

[[gnu::used, gnu::const]] extern uint32_t __remill_undefined_32(void);

[[gnu::used, gnu::const]] extern uint64_t __remill_undefined_64(void);

[[gnu::used, gnu::const]] extern float32_t __remill_undefined_f32(void);

[[gnu::used, gnu::const]] extern float64_t __remill_undefined_f64(void);

[[gnu::used, gnu::const]] extern float80_t __remill_undefined_f80(void);

[[gnu::used, gnu::const]] extern float128_t __remill_undefined_f128(void);

[[gnu::used, gnu::const]] extern bool
__remill_flag_computation_zero(bool result, ...);

[[gnu::used, gnu::const]] extern bool
__remill_flag_computation_sign(bool result, ...);

[[gnu::used, gnu::const]] extern bool
__remill_flag_computation_overflow(bool result, ...);

[[gnu::used, gnu::const]] extern bool
__remill_flag_computation_carry(bool result, ...);

[[gnu::used, gnu::const]] extern bool __remill_compare_sle(bool result);

[[gnu::used, gnu::const]] extern bool __remill_compare_slt(bool result);

[[gnu::used, gnu::const]] extern bool __remill_compare_sge(bool result);

[[gnu::used, gnu::const]] extern bool __remill_compare_sgt(bool result);


[[gnu::used, gnu::const]] extern bool __remill_compare_ule(bool result);

[[gnu::used, gnu::const]] extern bool __remill_compare_ult(bool result);

[[gnu::used, gnu::const]] extern bool __remill_compare_ugt(bool result);

[[gnu::used, gnu::const]] extern bool __remill_compare_uge(bool result);

[[gnu::used, gnu::const]] extern bool __remill_compare_eq(bool result);

[[gnu::used, gnu::const]] extern bool __remill_compare_neq(bool result);

// Generic error.
[[gnu::used]] extern Memory *__remill_error(State &, addr_t addr, Memory *);

// Control-flow intrinsics.
[[gnu::used]] extern Memory *__remill_function_call(State &, addr_t addr,
                                                    Memory *);

[[gnu::used]] extern Memory *__remill_function_return(State &, addr_t addr,
                                                      Memory *);

[[gnu::used]] extern Memory *__remill_jump(State &, addr_t addr, Memory *);

[[gnu::used]] extern Memory *__remill_missing_block(State &, addr_t addr,
                                                    Memory *);

[[gnu::used]] extern Memory *__remill_async_hyper_call(State &, addr_t ret_addr,
                                                       Memory *);

[[gnu::used]] extern Memory *__remill_sync_hyper_call(State &, Memory *,
                                                      SyncHyperCall::Name);

// Memory barriers types:
//  http://g.oswego.edu/dl/jmm/cookbook.html
//  http://preshing.com/20120913/acquire-and-release-semantics/
//  http://preshing.com/20120710/memory-barriers-are-like-source-control-operations/
[[gnu::used, gnu::const]] extern Memory *__remill_barrier_load_load(Memory *);

[[gnu::used, gnu::const]] extern Memory *
__remill_barrier_load_store(Memory *);  // Load acquire.

[[gnu::used, gnu::const]] extern Memory *__remill_barrier_store_load(Memory *);

[[gnu::used, gnu::const]] extern Memory *
__remill_barrier_store_store(Memory *);  // Store release.

// Atomic operations. The address/size are hints, but the granularity of the
// access can be bigger. These have implicit StoreLoad semantics.
[[gnu::used, gnu::const]] extern Memory *__remill_atomic_begin(Memory *);

[[gnu::used, gnu::const]] extern Memory *__remill_atomic_end(Memory *);

// Used to signal the begin/ending of an instruction executed within a delay
// slot.
[[gnu::used, gnu::const]] extern Memory *__remill_delay_slot_begin(Memory *);

[[gnu::used, gnu::const]] extern Memory *__remill_delay_slot_end(Memory *);

/* Most memory intrinsics are marked as `[[gnu::const]]` which tells the compiler that they
 * do not read/write to memory. This permits LLVM to optimize around the intrinsic, without thinking
 * about it's internals.
 * The meaning of `[[gnu::const]]` is the function will neither read nor write to the memory. In
 * This case the previous value of memory at `addr` needs to be communicated back to the program
 * which will happen by writing back to the refernecs of `expected`. If the function were declared
 * with `[[gnu::const]]`, the compiler is free to assume that the value of `expected` is not changed
 * and it will cause the unwanted behavior.
 *
 * The `gnu::pure` attribute causes the unwanted behaviour and the argument references updated inside
 * the function are not visible in the caller functions
 */


[[gnu::used]] extern Memory *
__remill_compare_exchange_memory_8(Memory *, addr_t addr, uint8_t &expected,
                                   uint8_t desired);

[[gnu::used]] extern Memory *
__remill_compare_exchange_memory_16(Memory *, addr_t addr, uint16_t &expected,
                                    uint16_t desired);

[[gnu::used]] extern Memory *
__remill_compare_exchange_memory_32(Memory *, addr_t addr, uint32_t &expected,
                                    uint32_t desired);

[[gnu::used]] extern Memory *
__remill_compare_exchange_memory_64(Memory *, addr_t addr, uint64_t &expected,
                                    uint64_t desired);

[[gnu::used]] extern Memory *
__remill_compare_exchange_memory_128(Memory *, addr_t addr, uint128_t &expected,
                                     uint128_t &desired);

[[gnu::used]] extern Memory *__remill_fetch_and_add_8(Memory *, addr_t addr,
                                                      uint8_t &value);

[[gnu::used]] extern Memory *__remill_fetch_and_add_16(Memory *, addr_t addr,
                                                       uint16_t &value);

[[gnu::used]] extern Memory *__remill_fetch_and_add_32(Memory *, addr_t addr,
                                                       uint32_t &value);

[[gnu::used]] extern Memory *__remill_fetch_and_add_64(Memory *, addr_t addr,
                                                       uint64_t &value);

[[gnu::used]] extern Memory *__remill_fetch_and_sub_8(Memory *, addr_t addr,
                                                      uint8_t &value);

[[gnu::used]] extern Memory *__remill_fetch_and_sub_16(Memory *, addr_t addr,
                                                       uint16_t &value);

[[gnu::used]] extern Memory *__remill_fetch_and_sub_32(Memory *, addr_t addr,
                                                       uint32_t &value);

[[gnu::used]] extern Memory *__remill_fetch_and_sub_64(Memory *, addr_t addr,
                                                       uint64_t &value);

[[gnu::used]] extern Memory *__remill_fetch_and_and_8(Memory *, addr_t addr,
                                                      uint8_t &value);

[[gnu::used]] extern Memory *__remill_fetch_and_and_16(Memory *, addr_t addr,
                                                       uint16_t &value);

[[gnu::used]] extern Memory *__remill_fetch_and_and_32(Memory *, addr_t addr,
                                                       uint32_t &value);

[[gnu::used]] extern Memory *__remill_fetch_and_and_64(Memory *, addr_t addr,
                                                       uint64_t &value);

[[gnu::used]] extern Memory *__remill_fetch_and_or_8(Memory *, addr_t addr,
                                                     uint8_t &value);

[[gnu::used]] extern Memory *__remill_fetch_and_or_16(Memory *, addr_t addr,
                                                      uint16_t &value);

[[gnu::used]] extern Memory *__remill_fetch_and_or_32(Memory *, addr_t addr,
                                                      uint32_t &value);

[[gnu::used]] extern Memory *__remill_fetch_and_or_64(Memory *, addr_t addr,
                                                      uint64_t &value);

[[gnu::used]] extern Memory *__remill_fetch_and_xor_8(Memory *, addr_t addr,
                                                      uint8_t &value);

[[gnu::used]] extern Memory *__remill_fetch_and_xor_16(Memory *, addr_t addr,
                                                       uint16_t &value);

[[gnu::used]] extern Memory *__remill_fetch_and_xor_32(Memory *, addr_t addr,
                                                       uint32_t &value);

[[gnu::used]] extern Memory *__remill_fetch_and_xor_64(Memory *, addr_t addr,
                                                       uint64_t &value);

[[gnu::used]] extern Memory *__remill_fetch_and_nand_8(Memory *, addr_t addr,
                                                       uint8_t &value);

[[gnu::used]] extern Memory *__remill_fetch_and_nand_16(Memory *, addr_t addr,
                                                        uint16_t &value);

[[gnu::used]] extern Memory *__remill_fetch_and_nand_32(Memory *, addr_t addr,
                                                        uint32_t &value);

[[gnu::used]] extern Memory *__remill_fetch_and_nand_64(Memory *, addr_t addr,
                                                        uint64_t &value);

// Read and modify the floating point exception state of the (virtual) machine
// that is executing the actual floating point operations.
//
//      auto old = __remill_fpu_exception_test_and_clear(0, FE_ALL_EXCEPT);
//      auto y = ...;
//      auto res = x op y;
//      auto flags = __remill_fpu_exception_test_and_clear(FE_ALL_EXCEPT, 0);
//
// These flags are also subject to optimizations
[[gnu::used, gnu::const]] extern int
__remill_fpu_exception_test_and_clear(int read_mask, int clear_mask);

// Read/write to I/O ports.
[[gnu::used, gnu::const]] extern uint8_t __remill_read_io_port_8(Memory *,
                                                                 addr_t);

[[gnu::used, gnu::const]] extern uint16_t __remill_read_io_port_16(Memory *,
                                                                   addr_t);

[[gnu::used, gnu::const]] extern uint32_t __remill_read_io_port_32(Memory *,
                                                                   addr_t);

[[gnu::used, gnu::const]] extern Memory *
__remill_write_io_port_8(Memory *, addr_t, uint8_t);

[[gnu::used, gnu::const]] extern Memory *
__remill_write_io_port_16(Memory *, addr_t, uint16_t);

[[gnu::used, gnu::const]] extern Memory *
__remill_write_io_port_32(Memory *, addr_t, uint32_t);

}  // extern C
