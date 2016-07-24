/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_BC_INTRINSICTABLE_H_
#define REMILL_BC_INTRINSICTABLE_H_

namespace llvm {
class Function;
class Module;
}  // namespace llvm
namespace remill {

class IntrinsicTable {
 public:
  IntrinsicTable(const llvm::Module *M);

  llvm::Function * const error;

  // Control-flow.
  llvm::Function * const function_call;
  llvm::Function * const function_return;
  llvm::Function * const jump;

  // OS interaction.
  llvm::Function * const system_call;
  llvm::Function * const system_return;
  llvm::Function * const interrupt_call;
  llvm::Function * const interrupt_return;

  // Arch interaction.
  llvm::Function * const read_cpu_features;

  // Block that can't be found.
  llvm::Function * const missing_block;

  // Memory read intrinsics.
  llvm::Function * const read_memory_8;
  llvm::Function * const read_memory_16;
  llvm::Function * const read_memory_32;
  llvm::Function * const read_memory_64;

  // Memory write intrinsics.
  llvm::Function * const write_memory_8;
  llvm::Function * const write_memory_16;
  llvm::Function * const write_memory_32;
  llvm::Function * const write_memory_64;

  llvm::Function * const read_memory_f32;
  llvm::Function * const read_memory_f64;
//  llvm::Function * const read_memory_f80;

  llvm::Function * const write_memory_f32;
  llvm::Function * const write_memory_f64;
//  llvm::Function * const write_memory_f80;
//
//  llvm::Function * const read_f80;
//  llvm::Function * const write_f80;

  // Addressing intrinsics.
  llvm::Function * const compute_address;

  // Memory barriers.
  llvm::Function * const barrier_load_load;
  llvm::Function * const barrier_load_store;
  llvm::Function * const barrier_store_load;
  llvm::Function * const barrier_store_store;

  llvm::Function * const atomic_begin;
  llvm::Function * const atomic_end;

  // Optimization control.
  llvm::Function * const defer_inlining;

  // Optimization enabling.
  llvm::Function *undefined_bool;
  llvm::Function *undefined_8;
  llvm::Function *undefined_16;
  llvm::Function *undefined_32;
  llvm::Function *undefined_64;
  llvm::Function *undefined_f32;
  llvm::Function *undefined_f64;

 private:
  IntrinsicTable(void) = delete;
};

}  // namespace remill

#endif  // REMILL_BC_INTRINSICTABLE_H_
