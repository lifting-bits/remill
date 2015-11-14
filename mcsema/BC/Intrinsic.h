/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_BC_INTRINSIC_H_
#define MCSEMA_BC_INTRINSIC_H_

namespace llvm {
class Function;
}  // namespace llvm
namespace mcsema {

class Intrinsic {
 public:
  static Intrinsic *FindInModule(llvm::Module *M);

  // Basic block template.
  llvm::Function * const basic_block;

  // Control-transfer intrinsics.
  llvm::Function * const error;
  llvm::Function * const function_call;
  llvm::Function * const function_return;
  llvm::Function * const jump;
  llvm::Function * const system_call;
  llvm::Function * const system_return;
  llvm::Function * const interrupt_call;
  llvm::Function * const interrupt_return;

  // Memory read intrinsics.
  llvm::Function * const read_memory_8;
  llvm::Function * const read_memory_16;
  llvm::Function * const read_memory_32;
  llvm::Function * const read_memory_64;
  llvm::Function * const read_memory_128;
  llvm::Function * const read_memory_256;
  llvm::Function * const read_memory_512;

  // Memory write intrinsics.
  llvm::Function * const write_memory_8;
  llvm::Function * const write_memory_16;
  llvm::Function * const write_memory_32;
  llvm::Function * const write_memory_64;
  llvm::Function * const write_memory_128;
  llvm::Function * const write_memory_256;
  llvm::Function * const write_memory_512;

  // Addressing intrinsics.
  llvm::Function * const compute_address;

  // Undefined values.
  llvm::Function * const undefined_bool;

 private:
  Intrinsic(void) = delete;
  explicit Intrinsic(llvm::Module *M);
};

}  // namespace mcsema

#endif  // MCSEMA_BC_INTRINSIC_H_
