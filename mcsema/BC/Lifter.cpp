/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <functional>
#include <set>
#include <string>
#include <sstream>

#include <llvm/ADT/SmallVector.h>

#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Type.h>

#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/ValueMapper.h>
#include <mcsema/BC/Lifter.h>
#include <mcsema/BC/Lifter.h>
#include "mcsema/Arch/Arch.h"
#include "mcsema/Arch/Instr.h"

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

// Find a specific function.
static llvm::Function *FindIntrinsic(llvm::Module *M, const char *name) {
  llvm::Function *F = nullptr;
  F = M->getFunction(name);
  if (!F && FLAGS_os == "mac") {
    F = M->getFunction(std::string("_") + name);
  }
  LOG_IF(FATAL, !F) << "Missing intrinsic " << name << "for OS: " << FLAGS_os;
  InitFunctionAttributes(F);

  F->setDoesNotAccessMemory();
  F->setCannotDuplicate();
  return F;
}

}  // namespace

Lifter::Lifter(const Arch *arch_, llvm::Module *module_)
    : arch(arch_),
      module(module_),
      blocks(),
      functions(),
      symbols(),
      next_symbol_id(0),
      basic_block(FindIntrinsic(module, "__mcsema_basic_block")),
      error(FindIntrinsic(module, "__mcsema_error")),
      function_call(FindIntrinsic(module, "__mcsema_function_call")),
      function_return(FindIntrinsic(module, "__mcsema_function_return")),
      jump(FindIntrinsic(module, "__mcsema_jump")),
      system_call(FindIntrinsic(module, "__mcsema_system_call")),
      system_return(FindIntrinsic(module, "__mcsema_system_return")),
      interrupt_call(FindIntrinsic(module, "__mcsema_interrupt_call")),
      interrupt_return(FindIntrinsic(module, "__mcsema_interrupt_return")),
      read_memory_8(FindIntrinsic(module, "__mcsema_read_memory_8")),
      read_memory_16(FindIntrinsic(module, "__mcsema_read_memory_16")),
      read_memory_32(FindIntrinsic(module, "__mcsema_read_memory_32")),
      read_memory_64(FindIntrinsic(module, "__mcsema_read_memory_64")),
      read_memory_128(FindIntrinsic(module, "__mcsema_read_memory_128")),
      read_memory_256(FindIntrinsic(module, "__mcsema_read_memory_256")),
      read_memory_512(FindIntrinsic(module, "__mcsema_read_memory_512")),
      write_memory_8(FindIntrinsic(module, "__mcsema_write_memory_8")),
      write_memory_16(FindIntrinsic(module, "__mcsema_write_memory_16")),
      write_memory_32(FindIntrinsic(module, "__mcsema_write_memory_32")),
      write_memory_64(FindIntrinsic(module, "__mcsema_write_memory_64")),
      write_memory_128(FindIntrinsic(module, "__mcsema_write_memory_128")),
      write_memory_256(FindIntrinsic(module, "__mcsema_write_memory_256")),
      write_memory_512(FindIntrinsic(module, "__mcsema_write_memory_512")),
      compute_address(FindIntrinsic(module, "__mcsema_compute_address")),
      undefined_bool(FindIntrinsic(module, "__mcsema_undefined_bool")){
  IdentifyExistingSymbols();
  RemoveUndefinedModules();
}

// Find existing exported functions and variables. This is for the sake of
// linking functions of the same names across CFG files.
void Lifter::IdentifyExistingSymbols(void) {
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
void Lifter::CreateBlocks(const cfg::Module *cfg) {
  auto block_type = basic_block->getFunctionType();
  for (const auto &block : cfg->blocks()) {
    auto &BF = blocks[block.address()];
    if (!BF) {
      std::stringstream ss;
      ss << "__lifted_block_" << (next_symbol_id++) << "_0x"
         << std::hex << block.address();
      BF = llvm::dyn_cast<llvm::Function>(
          module->getOrInsertFunction(ss.str(), block_type));
      InitFunctionAttributes(BF);
    }
  }
}

// Create functions for every function in the CFG.
void Lifter::CreateFunctions(const cfg::Module *cfg) {
  auto func_type = basic_block->getFunctionType();

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
void Lifter::LinkFunctionsToBlocks(const cfg::Module *cfg) {
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

}  // namespace

// Add a fall-through terminator to the block method just in case one is
// missing.
void Lifter::TerminateBlockMethod(const cfg::Block &block, llvm::Function *BF) {
  auto &B = BF->back();
  if (B.getTerminator()) {
    return;
  }
  if (block.instructions_size()) {
    AddTerminatingTailCall(BF, GetLiftedBlockForPC(FallThroughPC(block)));
  } else {
    LOG(WARNING) << "Empty basic block at " << block.address();
    AddTerminatingTailCall(BF, error);
  }
}

// Remove calls to the undefined intrinsics.
void Lifter::RemoveUndefinedModules(void) {
  std::vector<llvm::CallInst *> Cs;
  for (auto U : undefined_bool->users()) {
    if (auto C = llvm::dyn_cast<llvm::CallInst>(U)) {
      Cs.push_back(C);
    }
  }

  auto Undef = llvm::UndefValue::get(llvm::Type::getInt1Ty(
      undefined_bool->getContext()));
  for (auto C : Cs) {
    C->replaceAllUsesWith(Undef);
  }
}

// Lift code contained in blocks into the block methods.
void Lifter::LiftBlocks(const cfg::Module *cfg) {
  llvm::legacy::FunctionPassManager FPM(module);
  FPM.add(llvm::createDeadCodeEliminationPass());
  FPM.add(llvm::createCFGSimplificationPass());
  FPM.add(llvm::createPromoteMemoryToRegisterPass());
  FPM.add(llvm::createReassociatePass());
  FPM.add(llvm::createInstructionCombiningPass());
  FPM.add(llvm::createDeadStoreEliminationPass());

  for (const auto &block : cfg->blocks()) {
    LOG_IF(WARNING, 0 < block.instructions_size())
        << "Block at " << block.address() << " has no instructions!";

    auto BF = GetLiftedBlockForPC(block.address());
    if (!BF->isDeclaration()) {
      LOG(WARNING) << "Ignoring already lifted block at " << block.address();
      continue;
    }

    CreateMethodForBlock(BF, basic_block);
    if (block.instructions_size()) {
      LiftBlockIntoMethod(block, BF);
    }
    TerminateBlockMethod(block, BF);

    // Perform simple, incremental optimizations on the block functions to
    // avoid OOMs.
    FPM.run(*BF);
  }
}

void Lifter::LiftBlockIntoMethod(const cfg::Block &block, llvm::Function *BF) {
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
bool Lifter::LiftInstruction(const cfg::Block &block, const cfg::Instr &instr,
                         Instr &arch_instr, llvm::Function *BF) {
  std::stringstream ss;
  ss << std::hex << instr.address();

  // Create a block for this instruction.
  auto P = &(BF->back());
  auto B = llvm::BasicBlock::Create(BF->getContext(), ss.str(), BF);

  // Connect the block to its predecessor.
  llvm::IRBuilder<> ir(P);
  ir.CreateBr(B);

  return arch_instr.Lift(*this, B);
}

void Lifter::LiftCFG(const cfg::Module *cfg) {
  blocks.clear();  // Just in case we call `LiftCFG` multiple times.
  CreateBlocks(cfg);
  CreateFunctions(cfg);
  LinkFunctionsToBlocks(cfg);
  LiftBlocks(cfg);
}

llvm::Function *Lifter::GetLiftedBlockForPC(uintptr_t pc) const {
  return blocks[pc];
}

}  // namespace mcsema
