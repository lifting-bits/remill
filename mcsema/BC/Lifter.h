/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_BC_LIFTER_H_
#define MCSEMA_BC_LIFTER_H_

#include <string>

#include "mcsema/BC/Util.h"

namespace llvm {
class Function;
class Module;
class GlobalVariable;
}  // namespace llvm

namespace mcsema {
namespace cfg {
class Block;
class Instr;
class Module;
}  // namespace cfg

class Arch;
class Instr;
class Lifter;

// Lifts CFG files into a bitcode module.
class Lifter {
 public:
  Lifter(const Arch *arch_, llvm::Module *module_);

  // Lift the control-flow graph specified by `cfg` into this bitcode module.
  void LiftCFG(const cfg::Module *cfg);

 private:
  Lifter(void) = delete;
  Lifter(const Lifter &) = delete;

  // Identify symbols that are already present in the bitcode and can
  // therefore be used as a target for linking.
  void IdentifyExistingSymbols(void);

  // Create functions for every block in the CFG.
  void CreateBlocks(const cfg::Module *cfg);

  // Create functions for every imported/exported function in the code.
  void CreateFunctions(const cfg::Module *cfg);

  // Link together functions and basic blocks.
  void LinkFunctionsToBlocks(const cfg::Module *cfg);

  // Lift code contained in blocks into the block methods.
  void LiftBlocks(const cfg::Module *cfg);

  // Lift code contained in a block into a block method.
  void LiftBlockIntoMethod(const cfg::Block &block, llvm::Function *BF);

  // Lift an architecture-specific instruction.
  bool LiftInstruction(const cfg::Block &block, const cfg::Instr &instr,
                       Instr &ainstr, llvm::Function *BF);

  // Add a fall-through terminator to the block method just in case one is
  // missing.
  void TerminateBlockMethod(const cfg::Block &block, llvm::Function *BF);

  // Remove calls to the undefined intrinsics.
  void ReplaceUndefinedIntrinsics(void);

  // Architecture of the code contained within the CFG being lifted.
  const Arch * const arch;

  // Module into which code is lifted.
  llvm::Module * const module;

  // Blocks that we've added, indexed by their entry address.
  BlockMap blocks;

  // Named functions present in the module. These may be defined or only
  // declared.
  FunctionMap functions;

  // Named variables present within the module.
  SymbolMap symbols;

  // ID of the next symbol to add. We want to be able to merge CFGs from
  // multiple libraries, so it's not safe to just name blocks from those CFGs
  // with their address because they might conflict. So, we give a unique
  // name to every non-exported symbol we introduce.
  int next_symbol_id;

 public:

  llvm::Function *GetLiftedBlockForPC(uintptr_t pc) const;

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
  llvm::Function * const read_memory_v64;
  llvm::Function * const read_memory_v128;
  llvm::Function * const read_memory_v256;
  llvm::Function * const read_memory_v512;

  // Memory write intrinsics.
  llvm::Function * const write_memory_8;
  llvm::Function * const write_memory_16;
  llvm::Function * const write_memory_32;
  llvm::Function * const write_memory_64;
  llvm::Function * const write_memory_v64;
  llvm::Function * const write_memory_v128;
  llvm::Function * const write_memory_v256;
  llvm::Function * const write_memory_v512;

  // Addressing intrinsics.
  llvm::Function * const compute_address;

  // Undefined values.
  llvm::Function * const undefined_bool;
};

}  // namespace mcsema

#endif  // MCSEMA_BC_LIFTER_H_
