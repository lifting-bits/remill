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
class InstructionLifter;

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

  // Create a function for a single decoded block.
  void CreateBlock(const cfg::Block &block);

  // Create a function for a single block.
  llvm::Function *GetBlock(uint64_t address);

  // Lift code contained in blocks into the block methods.
  void LiftBlocks(const cfg::Module *cfg);

  // Lift code contained within a single block.
  llvm::Function *LiftBlock(const cfg::Block &block);

  // Lift the last instruction of a block as a block terminator.
  void LiftTerminator(llvm::BasicBlock *block,
                      const Instruction *instr);

  // Lift a single instruction into a basic block.
  llvm::BasicBlock *LiftInstruction(llvm::Function *block,
                                    Instruction *instr,
                                    InstructionLifter &lifter);

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

  // Blocks that we've added, indexed by their entry address and their ID.
  std::unordered_map<uint64_t, llvm::Function *> pc_to_block;
  std::unordered_map<uint64_t, llvm::Function *> id_to_block;

  // Basic block template.
  llvm::Function * const basic_block;

  // Machine word type for this architecture.
  llvm::IntegerType * const word_type;

 public:

  // Set of intrinsics.
  const IntrinsicTable * const intrinsics;
};

// Wraps the process of lifting an instruction into a block. This resolves
// the intended instruction target to a function, and ensures that the function
// is called with the appropriate arguments.
class InstructionLifter {
 public:
  virtual ~InstructionLifter(void);

  InstructionLifter(llvm::IntegerType *word_type_,
                    const IntrinsicTable *intrinsics_);

  // Lift a single instruction into a basic block.
  virtual bool LiftIntoBlock(Instruction *instr,
                             llvm::BasicBlock *block);

  // Machine word type for this architecture.
  llvm::IntegerType * const word_type;

  // Set of intrinsics.
  const IntrinsicTable * const intrinsics;

 protected:
  // Lift an operand to an instruction.
  virtual llvm::Value *LiftOperand(llvm::BasicBlock *block,
                                   llvm::Type *op_type,
                                   const Operand &op);

  // Lift a register operand to a value.
  virtual llvm::Value *LiftRegisterOperand(llvm::BasicBlock *block,
                                           llvm::Type *arg_type,
                                           const Operand::Register &reg);

  // Lift an immediate operand.
  virtual llvm::Value *LiftImmediateOperand(llvm::Type *arg_type,
                                            const Operand &op);

  // Lift an indirect memory operand to a value.
  virtual llvm::Value *LiftAddressOperand(llvm::BasicBlock *block,
                                          const Operand::Address &mem);

 private:
  InstructionLifter(void) = delete;
};

}  // namespace remill

#endif  // REMILL_BC_LIFTER_H_
