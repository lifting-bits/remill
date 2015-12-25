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

// Replace all uses of a specific intrinsic with an undefined value.
static void ReplaceIntrinsic(llvm::Function *F, unsigned N) {
  if (!F) return;

  std::vector<llvm::CallInst *> Cs;
  for (auto U : F->users()) {
    if (auto C = llvm::dyn_cast<llvm::CallInst>(U)) {
      Cs.push_back(C);
    }
  }

  auto Undef = llvm::UndefValue::get(llvm::Type::getIntNTy(F->getContext(), N));
  for (auto C : Cs) {
    C->replaceAllUsesWith(Undef);
    C->removeFromParent();
    delete C;
  }
}

}  // namespace

IntrinsicTable::IntrinsicTable(const llvm::Module *M)
    : error(FindIntrinsic(M, "__mcsema_error")),

      // Control-flow.
      function_call(FindIntrinsic(M, "__mcsema_function_call")),
      function_return(FindIntrinsic(M, "__mcsema_function_return")),
      jump(FindIntrinsic(M, "__mcsema_jump")),

      // OS interaction.
      system_call(FindIntrinsic(M, "__mcsema_system_call")),
      system_return(FindIntrinsic(M, "__mcsema_system_return")),
      interrupt_call(FindIntrinsic(M, "__mcsema_interrupt_call")),
      interrupt_return(FindIntrinsic(M, "__mcsema_interrupt_return")),

      // Memory access.
      read_memory_8(FindPureIntrinsic(M, "__mcsema_read_memory_8")),
      read_memory_16(FindPureIntrinsic(M, "__mcsema_read_memory_16")),
      read_memory_32(FindPureIntrinsic(M, "__mcsema_read_memory_32")),
      read_memory_64(FindPureIntrinsic(M, "__mcsema_read_memory_64")),
      read_memory_v64(FindPureIntrinsic(M, "__mcsema_read_memory_v64")),
      read_memory_v128(FindPureIntrinsic(M, "__mcsema_read_memory_v128")),
      read_memory_v256(FindPureIntrinsic(M, "__mcsema_read_memory_v256")),
      read_memory_v512(FindPureIntrinsic(M, "__mcsema_read_memory_v512")),
      write_memory_8(FindIntrinsic(M, "__mcsema_write_memory_8")),
      write_memory_16(FindIntrinsic(M, "__mcsema_write_memory_16")),
      write_memory_32(FindIntrinsic(M, "__mcsema_write_memory_32")),
      write_memory_64(FindIntrinsic(M, "__mcsema_write_memory_64")),
      write_memory_v64(FindIntrinsic(M, "__mcsema_write_memory_v64")),
      write_memory_v128(FindIntrinsic(M, "__mcsema_write_memory_v128")),
      write_memory_v256(FindIntrinsic(M, "__mcsema_write_memory_v256")),
      write_memory_v512(FindIntrinsic(M, "__mcsema_write_memory_v512")),
      compute_address(FindPureIntrinsic(M, "__mcsema_compute_address")),

      // Memory barriers.
      barrier_load_load(FindIntrinsic(M, "__mcsema_barrier_load_load")),
      barrier_load_store(FindIntrinsic(M, "__mcsema_barrier_load_store")),
      barrier_store_load(FindIntrinsic(M, "__mcsema_barrier_store_load")),
      barrier_store_store(FindIntrinsic(M, "__mcsema_barrier_store_store")),
      barrier_atomic_begin(FindIntrinsic(M, "__mcsema_barrier_atomic_begin")),
      barrier_atomic_end(FindIntrinsic(M, "__mcsema_barrier_atomic_end")),

      // Optimization guides.
      defer_inlining(FindIntrinsic(M, "__mcsema_defer_inlining")) {

  // Remove calls to the undefined intrinsics. The goal here is to improve dead
  // store elimination by peppering the instruction semantics with assignments
  // to the return values of special `__mcsema_undefined_*` intrinsics. It's hard
  // to reliably produce an `undef` LLVM value from C/C++, so we use our trick
  // of declaring (but never defining) a special "intrinsic" and then we replace
  // all such uses with `undef` values.
  ReplaceIntrinsic(FindIntrinsic(M, "__mcsema_undefined_bool"), 1);
  ReplaceIntrinsic(FindIntrinsic(M, "__mcsema_undefined_8"), 8);
  ReplaceIntrinsic(FindIntrinsic(M, "__mcsema_undefined_16"), 16);
  ReplaceIntrinsic(FindIntrinsic(M, "__mcsema_undefined_32"), 32);
  ReplaceIntrinsic(FindIntrinsic(M, "__mcsema_undefined_64"), 64);
}

}  // namespace mcsema
