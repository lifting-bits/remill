/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_BC_BC_H_
#define MCSEMA_BC_BC_H_

#include <string>

#include "mcsema/BC/Util.h"

namespace llvm {
class Function;
class Module;
class GlobalVariable;
}  // namespace llvm

namespace mcsema {
namespace cfg {
class Module;
class Block;
}  // namespace cfg

class Arch;

class BC {
 public:
  BC(const Arch *arch_, llvm::Module *module_);

  // Lift the control-flow graph specified by `cfg` into this bitcode module.
  void LiftCFG(const cfg::Module *cfg);

 private:
  BC(void) = delete;
  BC(const BC &) = delete;

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

  // Functions inside of `module` that we will clone for creating new function /
  // block methods.
  llvm::Function * const method;
};

}  // namespace mcsema

#endif  // MCSEMA_BC_BC_H_
