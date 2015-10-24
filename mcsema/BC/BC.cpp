/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <functional>
#include <set>
#include <string>
#include <sstream>

#include <llvm/ADT/SmallVector.h>

#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Type.h>

#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/ValueMapper.h>

#include "mcsema/Arch/Arch.h"
#include "mcsema/Arch/Instr.h"

#include "mcsema/BC/BC.h"
#include "mcsema/BC/Util.h"
#include "mcsema/CFG/CFG.h"

DECLARE_string(os);

namespace llvm {
class ReturnInst;
}  // namespace

namespace mcsema {
namespace {

// Name of some meta-data that we use to distinguish between external symbols
// and private symbols.
static std::string NamedSymbolMetaId(std::string func_name) {
  return "mcsema_external:" + func_name;
}

// Find the block method template by name.
static llvm::Function *BlockMethod(llvm::Module *M) {
  if (FLAGS_os == "linux") {
    return M->getFunction("_ZN5State5BlockEv");
  } else {
    LOG(FATAL) << "Missing block method name for OS: " << FLAGS_os;
    return nullptr;
  }
}

}  // namespace

BC::BC(const Arch *arch_, llvm::Module *module_)
    : arch(arch_),
      module(module_),
      blocks(),
      functions(),
      symbols(),
      next_symbol_id(0),
      method(BlockMethod(module)) {
  IdentifyExistingSymbols();
  InitFunctionAttributes(method);
}

// Find existing exported functions and variables. This is for the sake of
// linking functions of the same names across CFG files.
void BC::IdentifyExistingSymbols(void) {
  for (auto &F : module->functions()) {
    std::string name = F.getName();
    if (module->getNamedMetadata(NamedSymbolMetaId(name))) {
      functions[name] = &F;
    }
    ++next_symbol_id;
  }

  for (auto &V : module->globals()) {
    std::string name = V.getName();
    if (module->getNamedMetadata(NamedSymbolMetaId(name))) {
      symbols[name] = &V;
    }
    ++next_symbol_id;
  }
}

// Create functions for every block in the CFG.
void BC::CreateBlocks(const cfg::Module *cfg) {
  auto block_type = method->getFunctionType();
  for (const auto &block : cfg->blocks()) {
    auto &BF = blocks[block.address()];
    if (!BF) {
      auto name = "__mcsema_block_" + std::to_string(next_symbol_id++);
      BF = llvm::dyn_cast<llvm::Function>(
          module->getOrInsertFunction(name, block_type));
      InitFunctionAttributes(BF);
    }
  }
}

// Create functions for every function in the CFG.
void BC::CreateFunctions(const cfg::Module *cfg) {
  auto func_type = method->getFunctionType();

  for (const auto &func : cfg->functions()) {
    if (!func.is_exported() && !func.is_imported()) continue;

    CHECK(!func.name().empty())
        << "Module contains unnamed function at address " << func.address();

    CHECK(!(func.is_exported() && func.is_imported()))
        << "Function " << func.name() << " can't be imported and exported.";

    auto &F = functions[func.name()];
    if (!F) {
      F = llvm::dyn_cast<llvm::Function>(
          module->getOrInsertFunction(func.name(), func_type));

      InitFunctionAttributes(F);
    }

    // Mark this symbol as external. We do this so that we can pick up on it
    // if we merge another CFG into this bitcode module.
    module->getOrInsertNamedMetadata(NamedSymbolMetaId(func.name()));
  }

}

// Link together functions and basic blocks.
void BC::LinkFunctionsToBlocks(const cfg::Module *cfg) {
  for (const auto &func : cfg->functions()) {
    if (!func.is_exported() && !func.is_imported()) continue;
    if (!func.address()) continue;

    auto F = functions[func.name()];
    auto &BF = blocks[func.address()];

    // In the case of an exported function, redirect the function's
    // implementation to a locally defined block.
    if (func.is_exported()) {
      CHECK(nullptr != BF)
          << "Exported function " << func.name() << " has no address!";

      CHECK(F->isDeclaration())
          << "Function " << func.name() << " is already defined!";

      AddTerminatingTailCall(F, BF);

    // In the case of ELF binaries, we tend to see a call to something like
    // `malloc@plt` that is responsible for finding and invoking the actual
    // `malloc` implementation. In this case, we want to treat the `malloc@plt`
    // block address as synonymous with the function.
    //
    // TODO(pag): What about versioned ELF symbols?
    } else if (func.is_imported()) {
      if (!BF) {
        BF = F;
      } else {
        AddTerminatingTailCall(BF, F);
      }
    }
  }
}

namespace {

// Clone the block method template `TF` into a specific method `BF` that
// will contain lifted code.
static void CreateMethodForBlock(llvm::Function *BF, const llvm::Function *TF) {
  llvm::ValueToValueMapTy var_map;
  auto targs = TF->arg_begin();
  auto bargs = BF->arg_begin();
  for (; targs != TF->arg_end(); ++targs, ++bargs) {
    var_map[&*targs] = &*bargs;
  }

  llvm::SmallVector<llvm::ReturnInst *, 1> returns;
  llvm::CloneFunctionInto(BF, TF, var_map, false, returns);

  InitFunctionAttributes(BF);

  auto R = returns[0];
  R->removeFromParent();
  delete R;
}

// Fall-through PC for a block.
static uint64_t FallThroughPC(const cfg::Block &block) {
  const auto &instr = block.instructions(block.instructions_size() - 1);
  return instr.address() + instr.size();
}

// Add a fall-through terminator to the block method just in case one is
// missing.
static void TerminateBlockMethod(const BlockMap &blocks,
                                 const cfg::Block &block,
                                 llvm::Function *BF) {
  auto &B = BF->back();
  if (!B.getTerminator()) {
    AddTerminatingTailCall(BF, blocks[FallThroughPC(block)]);
  }
}
}  // namespace

// Lift code contained in blocks into the block methods.
void BC::LiftBlocks(const cfg::Module *cfg) {
  llvm::legacy::FunctionPassManager FPM(module);
  FPM.add(llvm::createDeadCodeEliminationPass());
  FPM.add(llvm::createCFGSimplificationPass());
  FPM.add(llvm::createPromoteMemoryToRegisterPass());
  FPM.add(llvm::createReassociatePass());
  FPM.add(llvm::createInstructionCombiningPass());

  for (const auto &block : cfg->blocks()) {
    CHECK(0 < block.instructions_size())
        << "Block at " << block.address() << " has no instructions!";

    auto BF = blocks[block.address()];

    CHECK(BF->isDeclaration())
        << "Block at " << block.address() << " is already defined!";

    CreateMethodForBlock(BF, method);
    LiftBlockIntoMethod(block, BF);
    TerminateBlockMethod(blocks, block, BF);

    // Perform simple, incremental optimizations on the block functions to
    // avoid OOMs.
    FPM.run(*BF);
  }
}

void BC::LiftBlockIntoMethod(const cfg::Block &block, llvm::Function *BF) {
  for (const auto &instr : block.instructions()) {
    CHECK(0 < instr.size())
        << "Can't decode zero-sized instruction at " << instr.address();

    CHECK(instr.size() == instr.bytes().length())
        << "Instruction size mismatch for instruction at " << instr.address();

    // Decode and lift an instruction. This may or may not finalize the block.
    bool continue_lifting = false;
    arch->Decode(instr, [&] (Instr &arch_instr) {
      continue_lifting = LiftInstruction(block, instr, arch_instr, BF);
    });

    if (!continue_lifting) break;
  }
}

// Lift an architecture-specific instruction.
bool BC::LiftInstruction(const cfg::Block &block, const cfg::Instr &instr,
                         Instr &arch_instr, llvm::Function *BF) {
  std::stringstream ss;
  ss << std::hex << instr.address();

  // Create a block for this instruction.
  auto P = &(BF->back());
  auto B = llvm::BasicBlock::Create(BF->getContext(), ss.str(), BF);

  // Connect the block to its predecessor.
  llvm::IRBuilder<> ir(P);
  ir.CreateBr(B);

  return arch_instr.Lift(blocks, B);
}

void BC::LiftCFG(const cfg::Module *cfg) {
  blocks.clear();  // Just in case we call `LiftCFG` multiple times.
  CreateBlocks(cfg);
  CreateFunctions(cfg);
  LinkFunctionsToBlocks(cfg);
  LiftBlocks(cfg);
}

}  // namespace mcsema
