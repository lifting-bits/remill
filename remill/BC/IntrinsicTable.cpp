/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <vector>

#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>

#include "remill/BC/IntrinsicTable.h"
#include "remill/BC/Util.h"

namespace remill {
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

//// Find a specific function.
//static llvm::Function *FindReadOnlyIntrinsic(const llvm::Module *module,
//                                             const char *name) {
//  auto function = FindIntrinsic(module, name);
//
//  // We want memory intrinsics to be marked as not accessing memory so that
//  // they don't interfere with dead store elimination.
//  function->addFnAttr(llvm::Attribute::ReadOnly);
//  return function;
//}

}  // namespace

IntrinsicTable::IntrinsicTable(const llvm::Module *module)
    : error(FindIntrinsic(module, "__remill_error")),

      // Control-flow.
      function_call(FindIntrinsic(module, "__remill_function_call")),
      function_return(FindIntrinsic(module, "__remill_function_return")),
      jump(FindIntrinsic(module, "__remill_jump")),

      // Signaling control-flow.
      create_program_counter(FindPureIntrinsic(
          module, "__remill_create_program_counter")),
      conditional_branch(FindPureIntrinsic(
          module, "__remill_conditional_branch")),

      // OS interaction.
      system_call(FindIntrinsic(module, "__remill_system_call")),
      system_return(FindIntrinsic(module, "__remill_system_return")),
      interrupt_call(FindIntrinsic(module, "__remill_interrupt_call")),
      interrupt_return(FindIntrinsic(module, "__remill_interrupt_return")),

      // Arch interaction.
      read_cpu_features(FindIntrinsic(module, "__remill_read_cpu_features")),

      // Block that can't be found.
      missing_block(FindIntrinsic(module, "__remill_missing_block")),

      // Memory access.
      read_memory_8(FindPureIntrinsic(module, "__remill_read_memory_8")),
      read_memory_16(FindPureIntrinsic(module, "__remill_read_memory_16")),
      read_memory_32(FindPureIntrinsic(module, "__remill_read_memory_32")),
      read_memory_64(FindPureIntrinsic(module, "__remill_read_memory_64")),

      write_memory_8(FindPureIntrinsic(module, "__remill_write_memory_8")),
      write_memory_16(FindPureIntrinsic(module, "__remill_write_memory_16")),
      write_memory_32(FindPureIntrinsic(module, "__remill_write_memory_32")),
      write_memory_64(FindPureIntrinsic(module, "__remill_write_memory_64")),

      read_memory_f32(FindPureIntrinsic(module, "__remill_read_memory_f32")),
      read_memory_f64(FindPureIntrinsic(module, "__remill_read_memory_f64")),
//      read_memory_f80(FindIntrinsic(module, "__remill_read_memory_f80")),

      write_memory_f32(FindPureIntrinsic(module, "__remill_write_memory_f32")),
      write_memory_f64(FindPureIntrinsic(module, "__remill_write_memory_f64")),
//      write_memory_f80(FindReadOnlyIntrinsic(
//          module, "__remill_write_memory_f80")),
//
//      read_f80(FindIntrinsic(module, "__remill_read_f80")),
//      write_f80(FindIntrinsic(module, "__remill_write_f80")),

      compute_address(FindPureIntrinsic(module, "__remill_compute_address")),

      // Memory barriers.
      barrier_load_load(FindPureIntrinsic(
          module, "__remill_barrier_load_load")),
      barrier_load_store(FindPureIntrinsic(
          module, "__remill_barrier_load_store")),
      barrier_store_load(FindPureIntrinsic(
          module, "__remill_barrier_store_load")),
      barrier_store_store(FindPureIntrinsic(
          module, "__remill_barrier_store_store")),
      atomic_begin(FindPureIntrinsic(module, "__remill_atomic_begin")),
      atomic_end(FindPureIntrinsic(module, "__remill_atomic_end")),

      // Optimization guides.
      //
      // Note:  NOT pure! This is a total hack: we call an unpure function
      //        within a pure one so that it is not optimized out!
      defer_inlining(FindIntrinsic(module, "__remill_defer_inlining")),

      // Optimization enablers.
      undefined_bool(FindPureIntrinsic(module, "__remill_undefined_bool")),
      undefined_8(FindPureIntrinsic(module, "__remill_undefined_8")),
      undefined_16(FindPureIntrinsic(module, "__remill_undefined_16")),
      undefined_32(FindPureIntrinsic(module, "__remill_undefined_32")),
      undefined_64(FindPureIntrinsic(module, "__remill_undefined_64")),
      undefined_f32(FindPureIntrinsic(module, "__remill_undefined_f32")),
      undefined_f64(FindPureIntrinsic(module, "__remill_undefined_f64")) {}

}  // namespace remill
