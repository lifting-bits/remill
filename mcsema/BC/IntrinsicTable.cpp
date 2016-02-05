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
static llvm::Function *FindIntrinsic(const llvm::Module *M, const char *name) {
  llvm::Function *F = FindFunction(M, name);
  LOG_IF(FATAL, !F) << "Unable to find intrinsic: " << name;

  InitFunctionAttributes(F);

  // We don't want calls to memory intrinsics to be duplicated because then
  // they might have the wrong side effects!
  F->addFnAttr(llvm::Attribute::NoDuplicate);

  return F;
}

// Find a specific function.
static llvm::Function *FindPureIntrinsic(const llvm::Module *M,
                                         const char *name) {
  auto F = FindIntrinsic(M, name);

  // We want memory intrinsics to be marked as not accessing memory so that
  // they don't interfere with dead store elimination.
  F->addFnAttr(llvm::Attribute::ReadNone);
  return F;
}

}  // namespace

IntrinsicTable::IntrinsicTable(const llvm::Module *M)
    : error(FindIntrinsic(M, "__mcsema_error")),

      // Control-flow.
      function_call(FindIntrinsic(M, "__mcsema_function_call")),
      function_return(FindIntrinsic(M, "__mcsema_function_return")),
      jump(FindIntrinsic(M, "__mcsema_jump")),

      // Signaling control-flow.
      conditional_branch(FindPureIntrinsic(M, "__mcsema_conditional_branch")),

      // OS interaction.
      system_call(FindIntrinsic(M, "__mcsema_system_call")),
      system_return(FindIntrinsic(M, "__mcsema_system_return")),
      interrupt_call(FindIntrinsic(M, "__mcsema_interrupt_call")),
      interrupt_return(FindIntrinsic(M, "__mcsema_interrupt_return")),

      // Block that can't be found.
      undefined_block(FindIntrinsic(M, "__mcsema_undefined_block")),

      // Memory access.
      read_memory_8(FindPureIntrinsic(M, "__mcsema_read_memory_8")),
      read_memory_16(FindPureIntrinsic(M, "__mcsema_read_memory_16")),
      read_memory_32(FindPureIntrinsic(M, "__mcsema_read_memory_32")),
      read_memory_64(FindPureIntrinsic(M, "__mcsema_read_memory_64")),

      read_memory_v8(FindPureIntrinsic(M, "__mcsema_read_memory_v8")),
      read_memory_v16(FindPureIntrinsic(M, "__mcsema_read_memory_v16")),
      read_memory_v32(FindPureIntrinsic(M, "__mcsema_read_memory_v32")),
      read_memory_v64(FindPureIntrinsic(M, "__mcsema_read_memory_v64")),
      read_memory_v128(FindPureIntrinsic(M, "__mcsema_read_memory_v128")),
      read_memory_v256(FindPureIntrinsic(M, "__mcsema_read_memory_v256")),
      read_memory_v512(FindPureIntrinsic(M, "__mcsema_read_memory_v512")),
      write_memory_8(FindPureIntrinsic(M, "__mcsema_write_memory_8")),
      write_memory_16(FindPureIntrinsic(M, "__mcsema_write_memory_16")),
      write_memory_32(FindPureIntrinsic(M, "__mcsema_write_memory_32")),
      write_memory_64(FindPureIntrinsic(M, "__mcsema_write_memory_64")),

      write_memory_v8(FindPureIntrinsic(M, "__mcsema_write_memory_v8")),
      write_memory_v16(FindPureIntrinsic(M, "__mcsema_write_memory_v16")),
      write_memory_v32(FindPureIntrinsic(M, "__mcsema_write_memory_v32")),
      write_memory_v64(FindPureIntrinsic(M, "__mcsema_write_memory_v64")),
      write_memory_v128(FindPureIntrinsic(M, "__mcsema_write_memory_v128")),
      write_memory_v256(FindPureIntrinsic(M, "__mcsema_write_memory_v256")),
      write_memory_v512(FindPureIntrinsic(M, "__mcsema_write_memory_v512")),
      compute_address(FindPureIntrinsic(M, "__mcsema_compute_address")),

      // Memory barriers.
      barrier_load_load(FindIntrinsic(M, "__mcsema_barrier_load_load")),
      barrier_load_store(FindIntrinsic(M, "__mcsema_barrier_load_store")),
      barrier_store_load(FindIntrinsic(M, "__mcsema_barrier_store_load")),
      barrier_store_store(FindIntrinsic(M, "__mcsema_barrier_store_store")),
      atomic_begin(FindIntrinsic(M, "__mcsema_atomic_begin")),
      atomic_end(FindIntrinsic(M, "__mcsema_atomic_end")),

      // Optimization guides.
      defer_inlining(FindPureIntrinsic(M, "__mcsema_defer_inlining")),

      // Optimization enablers.
      undefined_bool(FindPureIntrinsic(M, "__mcsema_undefined_bool")),
      undefined_8(FindPureIntrinsic(M, "__mcsema_undefined_8")),
      undefined_16(FindPureIntrinsic(M, "__mcsema_undefined_16")),
      undefined_32(FindPureIntrinsic(M, "__mcsema_undefined_32")),
      undefined_64(FindPureIntrinsic(M, "__mcsema_undefined_64")),

      // Used for the global ordering of memory instructions.
      memory_order(FindGlobaVariable(M, "__mcsema_memory_order")) {
}

}  // namespace mcsema
