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

#include "remill/Arch/Runtime/Intrinsics.h"

#include "remill/Arch/Runtime/Operators.h"

#define USED(sym) __remill_mark_as_used(reinterpret_cast<const void *>(&sym))

// This is two big hacks:
//    1)  This makes sure that a symbol is treated as used and prevents it
//        from being optimized away.
//    2)  This makes sure that some functions are marked has having their
//        addresses taken, and so this prevents dead argument elimination.
extern "C" void __remill_mark_as_used(const void *);

// This is just a hack to make sure all these functions appear in the bitcode
// file!
[[gnu::used]] extern "C" void __remill_intrinsics(void) {

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
  USED(__remill_read_memory_f128);

  USED(__remill_write_memory_f32);
  USED(__remill_write_memory_f64);
  USED(__remill_write_memory_f80);
  USED(__remill_write_memory_f128);

  USED(__remill_barrier_load_load);
  USED(__remill_barrier_load_store);
  USED(__remill_barrier_store_load);
  USED(__remill_barrier_store_store);

  USED(__remill_atomic_begin);
  USED(__remill_atomic_end);

  USED(__remill_delay_slot_begin);
  USED(__remill_delay_slot_end);

  // Atomic intrinsics
  USED(__remill_compare_exchange_memory_8);
  USED(__remill_compare_exchange_memory_16);
  USED(__remill_compare_exchange_memory_32);
  USED(__remill_compare_exchange_memory_64);

  USED(__remill_fetch_and_add_8);
  USED(__remill_fetch_and_add_16);
  USED(__remill_fetch_and_add_32);
  USED(__remill_fetch_and_add_64);

  USED(__remill_fetch_and_sub_8);
  USED(__remill_fetch_and_sub_16);
  USED(__remill_fetch_and_sub_32);
  USED(__remill_fetch_and_sub_64);

  USED(__remill_fetch_and_or_8);
  USED(__remill_fetch_and_or_16);
  USED(__remill_fetch_and_or_32);
  USED(__remill_fetch_and_or_64);

  USED(__remill_fetch_and_and_8);
  USED(__remill_fetch_and_and_16);
  USED(__remill_fetch_and_and_32);
  USED(__remill_fetch_and_and_64);

  USED(__remill_fetch_and_xor_8);
  USED(__remill_fetch_and_xor_16);
  USED(__remill_fetch_and_xor_32);
  USED(__remill_fetch_and_xor_64);

  USED(__remill_fpu_exception_test_and_clear);

  //  USED(__remill_defer_inlining);

  USED(__remill_error);

  USED(__remill_function_call);
  USED(__remill_function_return);
  USED(__remill_jump);
  USED(__remill_missing_block);

  USED(__remill_async_hyper_call);
  USED(__remill_sync_hyper_call);

  USED(__remill_undefined_8);
  USED(__remill_undefined_16);
  USED(__remill_undefined_32);
  USED(__remill_undefined_64);
  USED(__remill_undefined_f32);
  USED(__remill_undefined_f64);
  USED(__remill_undefined_f80);

  USED(__remill_flag_computation_zero);
  USED(__remill_flag_computation_overflow);
  USED(__remill_flag_computation_sign);
  USED(__remill_flag_computation_carry);

  USED(__remill_compare_sle);
  USED(__remill_compare_slt);
  USED(__remill_compare_sgt);
  USED(__remill_compare_sge);

  USED(__remill_compare_eq);
  USED(__remill_compare_neq);

  USED(__remill_compare_ugt);
  USED(__remill_compare_uge);
  USED(__remill_compare_ult);
  USED(__remill_compare_ule);
}
