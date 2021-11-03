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

#include <memory>

namespace llvm {
class ConstantArray;
class Function;
class Module;
class Value;
}  // namespace llvm
namespace remill {

class IntrinsicTable {
 public:
  inline explicit IntrinsicTable(const std::unique_ptr<llvm::Module> &module)
      : IntrinsicTable(module.get()) {}

  explicit IntrinsicTable(llvm::Module *module);

  llvm::Function *const error;

  // Control-flow.
  llvm::Function *const function_call;
  llvm::Function *const function_return;
  llvm::Function *const jump;
  llvm::Function *const missing_block;

  // OS interaction.
  llvm::Function *const async_hyper_call;

  // Memory read intrinsics.
  llvm::Function *const read_memory_8;
  llvm::Function *const read_memory_16;
  llvm::Function *const read_memory_32;
  llvm::Function *const read_memory_64;

  // Memory write intrinsics.
  llvm::Function *const write_memory_8;
  llvm::Function *const write_memory_16;
  llvm::Function *const write_memory_32;
  llvm::Function *const write_memory_64;

  llvm::Function *const read_memory_f32;
  llvm::Function *const read_memory_f64;
  llvm::Function *const read_memory_f80;
  llvm::Function *const read_memory_f128;

  llvm::Function *const write_memory_f32;
  llvm::Function *const write_memory_f64;
  llvm::Function *const write_memory_f80;
  llvm::Function *const write_memory_f128;

  // Memory barriers.
  llvm::Function *const barrier_load_load;
  llvm::Function *const barrier_load_store;
  llvm::Function *const barrier_store_load;
  llvm::Function *const barrier_store_store;

  llvm::Function *const atomic_begin;
  llvm::Function *const atomic_end;

  llvm::Function *const delay_slot_begin;
  llvm::Function *const delay_slot_end;

  // Optimization enabling.
  llvm::Function *undefined_8;
  llvm::Function *undefined_16;
  llvm::Function *undefined_32;
  llvm::Function *undefined_64;
  llvm::Function *undefined_f32;
  llvm::Function *undefined_f64;
  llvm::Function *undefined_f80;


  // Flag markers
  llvm::Function *flag_computation_zero;
  llvm::Function *flag_computation_sign;
  llvm::Function *flag_computation_overflow;
  llvm::Function *flag_computation_carry;

  llvm::Function *compare_sle;
  llvm::Function *compare_sgt;
  llvm::Function *compare_eq;
  llvm::Function *compare_neq;


 private:
  IntrinsicTable(void) = delete;
};

}  // namespace remill
