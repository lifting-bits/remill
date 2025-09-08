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

#include "remill/BC/IntrinsicTable.h"

#include <glog/logging.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

#include <vector>

#include "remill/BC/Util.h"
#include "remill/BC/Version.h"

namespace remill {
namespace {

// Find a specific function.
static llvm::Function *FindIntrinsic(llvm::Module *module, const char *name) {
  auto function = FindFunction(module, name);
  CHECK(nullptr != function) << "Unable to find intrinsic: " << name;

  // We don't want calls to memory intrinsics to be duplicated because then
  // they might have the wrong side effects!
  function->addFnAttr(llvm::Attribute::NoDuplicate);

  InitFunctionAttributes(function);

  function->setLinkage(llvm::GlobalValue::ExternalLinkage);

  function->removeFnAttr(llvm::Attribute::AlwaysInline);
  function->removeFnAttr(llvm::Attribute::InlineHint);
  function->addFnAttr(llvm::Attribute::OptimizeNone);
  function->addFnAttr(llvm::Attribute::NoInline);

  return function;
}

}  // namespace

IntrinsicTable::IntrinsicTable(llvm::Module *module)
    : error(FindIntrinsic(module, "__remill_error")),

      // Control-flow.
      function_call(FindIntrinsic(module, "__remill_function_call")),
      function_return(FindIntrinsic(module, "__remill_function_return")),
      jump(FindIntrinsic(module, "__remill_jump")),
      missing_block(FindIntrinsic(module, "__remill_missing_block")),

      // OS interaction.
      sync_hyper_call(FindIntrinsic(module, "__remill_sync_hyper_call")),
      async_hyper_call(FindIntrinsic(module, "__remill_async_hyper_call")),
      set_coprocessor_reg(FindIntrinsic(module, "__remill_set_coprocessor_reg")),

      // Memory access.
      read_memory_8(FindIntrinsic(module, "__remill_read_memory_8")),
      read_memory_16(FindIntrinsic(module, "__remill_read_memory_16")),
      read_memory_32(FindIntrinsic(module, "__remill_read_memory_32")),
      read_memory_64(FindIntrinsic(module, "__remill_read_memory_64")),

      write_memory_8(FindIntrinsic(module, "__remill_write_memory_8")),
      write_memory_16(FindIntrinsic(module, "__remill_write_memory_16")),
      write_memory_32(FindIntrinsic(module, "__remill_write_memory_32")),
      write_memory_64(FindIntrinsic(module, "__remill_write_memory_64")),

      read_memory_f32(FindIntrinsic(module, "__remill_read_memory_f32")),
      read_memory_f64(FindIntrinsic(module, "__remill_read_memory_f64")),
      read_memory_f80(FindIntrinsic(module, "__remill_read_memory_f80")),
      read_memory_f128(FindIntrinsic(module, "__remill_read_memory_f128")),

      write_memory_f32(FindIntrinsic(module, "__remill_write_memory_f32")),
      write_memory_f64(FindIntrinsic(module, "__remill_write_memory_f64")),
      write_memory_f80(FindIntrinsic(module, "__remill_write_memory_f80")),
      write_memory_f128(
          FindIntrinsic(module, "__remill_write_memory_f128")),

      // Memory barriers.
      barrier_load_load(
          FindIntrinsic(module, "__remill_barrier_load_load")),
      barrier_load_store(
          FindIntrinsic(module, "__remill_barrier_load_store")),
      barrier_store_load(
          FindIntrinsic(module, "__remill_barrier_store_load")),
      barrier_store_store(
          FindIntrinsic(module, "__remill_barrier_store_store")),
      atomic_begin(FindIntrinsic(module, "__remill_atomic_begin")),
      atomic_end(FindIntrinsic(module, "__remill_atomic_end")),
      delay_slot_begin(FindIntrinsic(module, "__remill_delay_slot_begin")),
      delay_slot_end(FindIntrinsic(module, "__remill_delay_slot_end")),

      //      // Optimization guides.
      //      //
      //      // Note:  NOT pure! This is a total hack: we call an unpure function
      //      //        within a pure one so that it is not optimized out!
      //      defer_inlining(FindIntrinsic(module, "__remill_defer_inlining")),

      // Optimization enablers.
      undefined_8(FindIntrinsic(module, "__remill_undefined_8")),
      undefined_16(FindIntrinsic(module, "__remill_undefined_16")),
      undefined_32(FindIntrinsic(module, "__remill_undefined_32")),
      undefined_64(FindIntrinsic(module, "__remill_undefined_64")),
      undefined_f32(FindIntrinsic(module, "__remill_undefined_f32")),
      undefined_f64(FindIntrinsic(module, "__remill_undefined_f64")),
      undefined_f80(FindIntrinsic(module, "__remill_undefined_f80")),

      // Flag computations
      flag_computation_zero(
          FindIntrinsic(module, "__remill_flag_computation_zero")),
      flag_computation_sign(
          FindIntrinsic(module, "__remill_flag_computation_sign")),
      flag_computation_overflow(
          FindIntrinsic(module, "__remill_flag_computation_overflow")),
      flag_computation_carry(
          FindIntrinsic(module, "__remill_flag_computation_carry")),
      // compares
      compare_sle(FindIntrinsic(module, "__remill_compare_sle")),
      compare_sgt(FindIntrinsic(module, "__remill_compare_sgt")),
      compare_eq(FindIntrinsic(module, "__remill_compare_eq")),
      compare_neq(FindIntrinsic(module, "__remill_compare_neq")),

      lifted_function_type(error->getFunctionType()),
      state_ptr_type(llvm::dyn_cast<llvm::PointerType>(
          lifted_function_type->getParamType(kStatePointerArgNum))),
      pc_type(llvm::dyn_cast<llvm::IntegerType>(
          lifted_function_type->getParamType(kPCArgNum))),
      mem_ptr_type(llvm::dyn_cast<llvm::PointerType>(
          lifted_function_type->getParamType(kMemoryPointerArgNum))) {


  // Make sure to set the correct attributes on this to make sure that
  // it's never optimized away.
  (void) FindIntrinsic(module, "__remill_intrinsics");
}

}  // namespace remill
