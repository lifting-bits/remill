/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <llvm/IR/Module.h>

#include "mcsema/BC/Intrinsic.h"
#include "mcsema/BC/Util.h"

DECLARE_string(os);

namespace mcsema {
namespace {

// Find a specific function.
static llvm::Function *FindIntrinsic(llvm::Module *M, const char *name) {
  llvm::Function *F = nullptr;
  F = M->getFunction(name);
  if (!F && FLAGS_os == "mac") {
    F = M->getFunction(std::string("_") + name);
  }
  LOG_IF(FATAL, !F) << "Missing intrinsic " << name << "for OS: " << FLAGS_os;
  InitFunctionAttributes(F);

  F->setDoesNotAccessMemory();
  F->setCannotDuplicate();
  return F;
}

}  // namespace

Intrinsic::Intrinsic(llvm::Module *M)
    : basic_block(FindIntrinsic(M, "__mcsema_basic_block")),
      error(FindIntrinsic(M, "__mcsema_error")),
      function_call(FindIntrinsic(M, "__mcsema_function_call")),
      function_return(FindIntrinsic(M, "__mcsema_function_return")),
      jump(FindIntrinsic(M, "__mcsema_jump")),
      system_call(FindIntrinsic(M, "__mcsema_system_call")),
      system_return(FindIntrinsic(M, "__mcsema_system_return")),
      interrupt_call(FindIntrinsic(M, "__mcsema_interrupt_call")),
      interrupt_return(FindIntrinsic(M, "__mcsema_interrupt_return")),
      read_memory_8(FindIntrinsic(M, "__mcsema_read_memory_8")),
      read_memory_16(FindIntrinsic(M, "__mcsema_read_memory_16")),
      read_memory_32(FindIntrinsic(M, "__mcsema_read_memory_32")),
      read_memory_64(FindIntrinsic(M, "__mcsema_read_memory_64")),
      read_memory_128(FindIntrinsic(M, "__mcsema_read_memory_128")),
      read_memory_256(FindIntrinsic(M, "__mcsema_read_memory_256")),
      read_memory_512(FindIntrinsic(M, "__mcsema_read_memory_512")),
      write_memory_8(FindIntrinsic(M, "__mcsema_write_memory_8")),
      write_memory_16(FindIntrinsic(M, "__mcsema_write_memory_16")),
      write_memory_32(FindIntrinsic(M, "__mcsema_write_memory_32")),
      write_memory_64(FindIntrinsic(M, "__mcsema_write_memory_64")),
      write_memory_128(FindIntrinsic(M, "__mcsema_write_memory_128")),
      write_memory_256(FindIntrinsic(M, "__mcsema_write_memory_256")),
      write_memory_512(FindIntrinsic(M, "__mcsema_write_memory_512")),
      compute_address(FindIntrinsic(M, "__mcsema_compute_address")),
      undefined_bool(FindIntrinsic(M, "__mcsema_undefined_bool")) {}

Intrinsic *Intrinsic::FindInModule(llvm::Module *M) {
  return new Intrinsic(M);
}

}  // namespace mcsema
