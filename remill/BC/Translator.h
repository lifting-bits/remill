/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_BC_TRANSLATOR_H_
#define REMILL_BC_TRANSLATOR_H_

#include <map>
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

// Lifts CFG files into a bitcode module.
class Translator {
 public:
  Translator(const Arch *arch_, llvm::Module *module_);

  // Lift the control-flow graph specified by `cfg` into this bitcode module.
  void LiftCFG(const cfg::Module *cfg);

 private:
  Translator(void) = delete;
  Translator(const Translator &) = delete;

  // Enable deferred inlining. The goal is to support better dead-store
  // elimination for flags.
  void EnableDeferredInlining(void);

  // Identify functions that are already exported by this module.
  void GetNamedBlocks(
      std::map<std::string, llvm::Function *> &table,
      const char *table_name);

  // Recreate a global table of named blocks.
  void SetNamedBlocks(
      std::map<std::string, llvm::Function *> &table,
      const char *table_name);

  // Identify the already lifted basic blocks.
  void GetIndirectBlocks(void);

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
                                    const Instruction *instr);

  // Lift an operand to an instruction.
  llvm::Value *LiftOperand(llvm::BasicBlock *block,
                           llvm::Type *op_type,
                           const Operand &op);

  // Lift a register operand to a value.
  llvm::Value *LiftRegisterOperand(llvm::BasicBlock *block,
                                   llvm::Type *arg_type,
                                   const Operand::Register &reg);

  // Lift an immediate operand.
  llvm::Value *LiftImmediateOperand(llvm::BasicBlock *block,
                                    llvm::Type *arg_type,
                                    const Operand &op);

  // Lift an indirect memory operand to a value.
  llvm::Value *LiftMemoryOperand(llvm::BasicBlock *block,
                                 const Operand::Address &mem);

  // Architecture of the code contained within the CFG being lifted.
  const Arch * const arch;

  // Module into which code is lifted.
  llvm::Module * const module;

  // Blocks that we've added, indexed by their entry address.
  std::map<uint64_t, llvm::Function *> blocks;
  std::map<uint64_t, llvm::Function *> indirect_blocks;

  // Named functions present in the module.
  std::map<std::string, llvm::Function *> exported_blocks;
  std::map<std::string, llvm::Function *> imported_blocks;

  // Basic block template.
  llvm::Function * const basic_block;

  // Machine word type for this architecture.
  llvm::IntegerType *word_type;

 public:

  // Set of intrinsics.
  const IntrinsicTable * const intrinsics;
};

}  // namespace remill

#endif  // REMILL_BC_TRANSLATOR_H_
