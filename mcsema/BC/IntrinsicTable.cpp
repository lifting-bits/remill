/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <vector>

#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>

#include "mcsema/BC/IntrinsicTable.h"
#include "mcsema/BC/Util.h"

namespace mcsema {
namespace {

// Find a specific function.
static llvm::Function *FindIntrinsic(const llvm::Module *module,
                                     const char *name) {
  auto function = FindFunction(module, name);
  CHECK(nullptr != function)
      << "Unable to find intrinsic: " << name;

  // We don't want calls to memory intrinsics to be duplicated because then
  // they might have the wrong side effects!
  function->addFnAttr(llvm::Attribute::NoDuplicate);

  InitFunctionAttributes(function);
  return function;
}

// Find a specific function.
static llvm::Function *FindPureIntrinsic(const llvm::Module *module,
                                         const char *name) {
  auto function = FindIntrinsic(module, name);

  // We want memory intrinsics to be marked as not accessing memory so that
  // they don't interfere with dead store elimination.
  function->addFnAttr(llvm::Attribute::ReadNone);
  return function;
}

// Find a specific function.
static llvm::Function *FindReadOnlyIntrinsic(const llvm::Module *module,
                                             const char *name) {
  auto function = FindIntrinsic(module, name);

  // We want memory intrinsics to be marked as not accessing memory so that
  // they don't interfere with dead store elimination.
  function->addFnAttr(llvm::Attribute::ReadOnly);
  return function;
}

}  // namespace

IntrinsicTable::IntrinsicTable(const llvm::Module *module)
    : error(FindIntrinsic(module, "__mcsema_error")),

      // Control-flow.
      function_call(FindIntrinsic(module, "__mcsema_function_call")),
      function_return(FindIntrinsic(module, "__mcsema_function_return")),
      jump(FindIntrinsic(module, "__mcsema_jump")),

      // Signaling control-flow.
      create_program_counter(FindPureIntrinsic(
          module, "__mcsema_create_program_counter")),
      conditional_branch(FindPureIntrinsic(
          module, "__mcsema_conditional_branch")),

      // OS interaction.
      system_call(FindIntrinsic(module, "__mcsema_system_call")),
      system_return(FindIntrinsic(module, "__mcsema_system_return")),
      interrupt_call(FindIntrinsic(module, "__mcsema_interrupt_call")),
      interrupt_return(FindIntrinsic(module, "__mcsema_interrupt_return")),

      // Arch interaction.
      read_cpu_features(FindIntrinsic(module, "__mcsema_read_cpu_features")),

      // Block that can't be found.
      missing_block(FindIntrinsic(module, "__mcsema_missing_block")),

      // Memory access.
      read_memory_8(FindPureIntrinsic(module, "__mcsema_read_memory_8")),
      read_memory_16(FindPureIntrinsic(module, "__mcsema_read_memory_16")),
      read_memory_32(FindPureIntrinsic(module, "__mcsema_read_memory_32")),
      read_memory_64(FindPureIntrinsic(module, "__mcsema_read_memory_64")),

      // These take in a value by reference and modify it, therefore they are
      // NOT pure.
      read_memory_v8(FindIntrinsic(module, "__mcsema_read_memory_v8")),
      read_memory_v16(FindIntrinsic(module, "__mcsema_read_memory_v16")),
      read_memory_v32(FindIntrinsic(module, "__mcsema_read_memory_v32")),
      read_memory_v64(FindIntrinsic(module, "__mcsema_read_memory_v64")),
      read_memory_v128(FindIntrinsic(module, "__mcsema_read_memory_v128")),
      read_memory_v256(FindIntrinsic(module, "__mcsema_read_memory_v256")),
      read_memory_v512(FindIntrinsic(module, "__mcsema_read_memory_v512")),

      write_memory_8(FindPureIntrinsic(module, "__mcsema_write_memory_8")),
      write_memory_16(FindPureIntrinsic(module, "__mcsema_write_memory_16")),
      write_memory_32(FindPureIntrinsic(module, "__mcsema_write_memory_32")),
      write_memory_64(FindPureIntrinsic(module, "__mcsema_write_memory_64")),

      write_memory_v8(FindReadOnlyIntrinsic(module, "__mcsema_write_memory_v8")),
      write_memory_v16(FindReadOnlyIntrinsic(module, "__mcsema_write_memory_v16")),
      write_memory_v32(FindReadOnlyIntrinsic(module, "__mcsema_write_memory_v32")),
      write_memory_v64(FindReadOnlyIntrinsic(module, "__mcsema_write_memory_v64")),
      write_memory_v128(FindReadOnlyIntrinsic(
          module, "__mcsema_write_memory_v128")),
      write_memory_v256(FindReadOnlyIntrinsic(
          module, "__mcsema_write_memory_v256")),
      write_memory_v512(FindReadOnlyIntrinsic(
          module, "__mcsema_write_memory_v512")),

      read_memory_f32(FindIntrinsic(module, "__mcsema_read_memory_f32")),
      read_memory_f64(FindIntrinsic(module, "__mcsema_read_memory_f64")),
      read_memory_f80(FindIntrinsic(module, "__mcsema_read_memory_f80")),

      write_memory_f32(FindReadOnlyIntrinsic(
          module, "__mcsema_write_memory_f32")),
      write_memory_f64(FindReadOnlyIntrinsic(
          module, "__mcsema_write_memory_f64")),
      write_memory_f80(FindReadOnlyIntrinsic(
          module, "__mcsema_write_memory_f80")),

      read_f80(FindIntrinsic(module, "__mcsema_read_f80")),
      write_f80(FindIntrinsic(module, "__mcsema_write_f80")),

      compute_address(FindPureIntrinsic(module, "__mcsema_compute_address")),

      // Memory barriers.
      barrier_load_load(FindPureIntrinsic(
          module, "__mcsema_barrier_load_load")),
      barrier_load_store(FindPureIntrinsic(
          module, "__mcsema_barrier_load_store")),
      barrier_store_load(FindPureIntrinsic(
          module, "__mcsema_barrier_store_load")),
      barrier_store_store(FindPureIntrinsic(
          module, "__mcsema_barrier_store_store")),
      atomic_begin(FindPureIntrinsic(module, "__mcsema_atomic_begin")),
      atomic_end(FindPureIntrinsic(module, "__mcsema_atomic_end")),

      // Optimization guides.
      //
      // Note:  NOT pure! This is a total hack: we call an unpure function
      //        within a pure one so that it is not optimized out!
      defer_inlining(FindIntrinsic(module, "__mcsema_defer_inlining")),

      // Optimization enablers.
      undefined_bool(FindPureIntrinsic(module, "__mcsema_undefined_bool")),
      undefined_8(FindPureIntrinsic(module, "__mcsema_undefined_8")),
      undefined_16(FindPureIntrinsic(module, "__mcsema_undefined_16")),
      undefined_32(FindPureIntrinsic(module, "__mcsema_undefined_32")),
      undefined_64(FindPureIntrinsic(module, "__mcsema_undefined_64")),
      undefined_f32(FindPureIntrinsic(module, "__mcsema_undefined_f32")),
      undefined_f64(FindPureIntrinsic(module, "__mcsema_undefined_f64")),

      // Used for the global ordering of memory instructions.
      memory_order(FindGlobaVariable(module, "__mcsema_memory_order")) {}

}  // namespace mcsema
