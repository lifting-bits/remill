/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_BC_TRANSLATOR_H_
#define MCSEMA_BC_TRANSLATOR_H_

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

  // Basic block template.
  llvm::Function * const basic_block;

 public:

  llvm::Function *GetLiftedBlockForPC(uintptr_t pc) const;

  // Set of intrinsics.
  const IntrinsicTable * const intrinsics;
};

}  // namespace mcsema

#endif  // MCSEMA_BC_TRANSLATOR_H_
