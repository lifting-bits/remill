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

#ifndef REMILL_ARCH_RUNTIME_INTRINSICS_H_
#define REMILL_ARCH_RUNTIME_INTRINSICS_H_

#include "remill/Arch/Runtime/Types.h"
#include "remill/Arch/Runtime/HyperCall.h"

extern "C" {

// The basic block "template".
[[gnu::used]]
Memory *__remill_basic_block(Memory *memory, State &state, addr_t);

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
extern Memory *__remill_error(Memory *, State &, addr_t addr);

// Control-flow intrinsics.
[[gnu::used]]
extern Memory *__remill_function_call(Memory *, State &, addr_t addr);

[[gnu::used]]
extern Memory *__remill_function_return(Memory *, State &, addr_t addr);

[[gnu::used]]
extern Memory *__remill_jump(Memory *, State &, addr_t addr);

[[gnu::used]]
extern Memory *__remill_missing_block(Memory *, State &, addr_t addr);

[[gnu::used]]
extern Memory *__remill_async_hyper_call(Memory *, State &, addr_t ret_addr);

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
