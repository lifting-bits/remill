/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_BC_TRANSLATOR_H_
#define REMILL_BC_TRANSLATOR_H_

#include <string>

#include "remill/BC/ABI.h"
#include "remill/BC/Util.h"

namespace llvm {
class Function;
class Module;
class GlobalVariable;
}  // namespace llvm

namespace remill {
namespace cfg {
class Block;
class Instr;
class Module;
}  // namespace cfg

class Arch;
class Instr;
class IntrinsicTable;
class Translator;

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

  // Identify symbols that are already present in the bitcode and can
  // therefore be used as a target for linking.
  void IdentifyExistingSymbols(void);

  // Create functions for every imported/exported function.
  void CreateFunctionsForExternals(const cfg::Module *cfg);

  // Create functions for every block in the CFG.
  void CreateFunctionsForBlocks(const cfg::Module *cfg);

  // Create functions for every exported function in the code.
  llvm::Function *CreateExportedFunction(
      const std::string &name, uintptr_t addr);

  // Create functions for every imported function in the code.
  llvm::Function *CreateImportedFunction(
      const std::string &name, uintptr_t addr);

  // Link together functions and basic blocks.
  void LinkExternalFunctionsToBlocks(const cfg::Module *cfg);

  // Lift code contained in blocks into the block methods.
  void LiftBlocks(const cfg::Module *cfg);

  // Lift code contained in a block into a block method.
  void LiftInstructionInfoBlock(const cfg::Block &block, llvm::Function *BF);

  // Create a basic block for an instruction.
  void LiftInstructionIntoBlock(const cfg::Block &block,
                                const cfg::Instr &instr,
                                llvm::BasicBlock *B);

  // Add a fall-through terminator to the block method just in case one is
  // missing.
  void TryTerminateBlockMethod(const cfg::Block &block, llvm::Function *BF);

  // Run an architecture-specific data-flow analysis on the module.
  void AnalyzeCFG(const cfg::Module *cfg);

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

  // Basic block template.
  llvm::Function * const basic_block;

 public:

  // Set of intrinsics.
  const IntrinsicTable * const intrinsics;

  llvm::Function *GetLiftedBlockForPC(uintptr_t pc) const;
};

}  // namespace remill

#endif  // REMILL_BC_TRANSLATOR_H_
