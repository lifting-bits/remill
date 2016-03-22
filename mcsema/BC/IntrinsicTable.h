/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_BC_INTRINSICTABLE_H_
#define MCSEMA_BC_INTRINSICTABLE_H_

namespace llvm {
class Function;
class Module;
}  // namespace llvm
namespace mcsema {

class IntrinsicTable {
 public:
  IntrinsicTable(const llvm::Module *M);

  llvm::Function * const error;

  // Control-flow.
  llvm::Function * const function_call;
  llvm::Function * const function_return;
  llvm::Function * const jump;

  // Semantic.
  llvm::Function * const create_program_counter;
  llvm::Function * const conditional_branch;

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

  llvm::Function * const read_memory_v8;
  llvm::Function * const read_memory_v16;
  llvm::Function * const read_memory_v32;
  llvm::Function * const read_memory_v64;
  llvm::Function * const read_memory_v128;
  llvm::Function * const read_memory_v256;
  llvm::Function * const read_memory_v512;

  // Memory write intrinsics.
  llvm::Function * const write_memory_8;
  llvm::Function * const write_memory_16;
  llvm::Function * const write_memory_32;
  llvm::Function * const write_memory_64;

  llvm::Function * const write_memory_v8;
  llvm::Function * const write_memory_v16;
  llvm::Function * const write_memory_v32;
  llvm::Function * const write_memory_v64;
  llvm::Function * const write_memory_v128;
  llvm::Function * const write_memory_v256;
  llvm::Function * const write_memory_v512;

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

  // Sets up a global memory ordering.
  llvm::GlobalVariable *memory_order;

 private:
  IntrinsicTable(void) = delete;
};

}  // namespace mcsema

#endif  // MCSEMA_BC_INTRINSICTABLE_H_
