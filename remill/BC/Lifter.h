/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_BC_LIFTER_H_
#define REMILL_BC_LIFTER_H_

#include <unordered_map>
#include <string>

#include "remill/Arch/Instruction.h"

#include "remill/BC/ABI.h"
#include "remill/BC/Util.h"

namespace llvm {
class Function;
class Module;
class GlobalVariable;
class IntegerType;
}  // namespace llvm

namespace remill {
namespace cfg {
class Block;
class Instr;
class Module;
}  // namespace cfg

class Arch;
class IntrinsicTable;

// Lifts CFG files into a bitcode module. This is mostly a big bag of state
// needed for all the parts of of lifting to coordinate.
class Lifter {
 public:
  Lifter(const Arch *arch_, llvm::Module *module_);
  ~Lifter(void);

  // Lift the control-flow graph specified by `cfg` into this bitcode module.
  void LiftCFG(const cfg::Module *cfg);

 private:
  Lifter(void) = delete;
  Lifter(const Lifter &) = delete;

  // Enable deferred inlining. The goal is to support better dead-store
  // elimination for flags.
  void EnableDeferredInlining(void);

  // Recreate a global table of named blocks.
  void SetNamedBlocks(
      std::unordered_map<std::string, llvm::Function *> &table,
      const char *table_name);

  // Recreate the global table of indirectly addressible blocks.
  void SetIndirectBlocks(void);

  // Create functions for every exported and imported function.
  void CreateNamedBlocks(const cfg::Module *cfg);

  // Create functions for every block in the CFG.
  void CreateBlocks(const cfg::Module *cfg);

  // Create a function for a single block.
  llvm::Function *GetOrCreateBlock(uint64_t address);

  // Create functions for every imported function in the code.
  llvm::Function *CreateImportedFunction(
      const std::string &name, uintptr_t addr);

  // Lift code contained in blocks into the block methods.
  void LiftBlocks(const cfg::Module *cfg);

  // Lift code contained within a single block.
  llvm::Function *LiftBlock(const cfg::Block *block);

  // Lift the last instruction of a block as a block terminator.
  void LiftTerminator(llvm::BasicBlock *block,
                      const Instruction *instr);

  // Lift a single instruction into a basic block.
  llvm::BasicBlock *LiftInstruction(llvm::Function *block,
                                    Instruction *instr);

  // Lift an operand to an instruction.
  llvm::Value *LiftOperand(llvm::BasicBlock *block,
                           llvm::Type *op_type,
                           const Operand &op);

  // Lift a register operand to a value.
  llvm::Value *LiftRegisterOperand(llvm::BasicBlock *block,
                                   llvm::Type *arg_type,
                                   const Operand::Register &reg);

  // Lift an immediate operand.
  llvm::Value *LiftImmediateOperand(llvm::Type *arg_type,
                                    const Operand &op);

  // Lift an indirect memory operand to a value.
  llvm::Value *LiftAddressOperand(llvm::BasicBlock *block,
                                 const Operand::Address &mem);

  // Architecture of the code contained within the CFG being lifted.
  const Arch * const arch;

  // Module into which code is lifted.
  llvm::Module * const module;

  // Blocks that we've added, indexed by their entry address.
  std::unordered_map<uint64_t, llvm::Function *> blocks;
  std::unordered_map<uint64_t, llvm::Function *> indirect_blocks;

  // Named functions present in the module.
  std::unordered_map<std::string, llvm::Function *> exported_blocks;
  std::unordered_map<std::string, llvm::Function *> imported_blocks;

  // Basic block template.
  llvm::Function * const basic_block;

  // Machine word type for this architecture.
  llvm::IntegerType * const word_type;

 public:

  // Set of intrinsics.
  const IntrinsicTable * const intrinsics;
};

}  // namespace remill

#endif  // REMILL_BC_LIFTER_H_
