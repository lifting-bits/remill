/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>
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

#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/IntrinsicTable.h"
#include "mcsema/BC/Translator.h"
#include "mcsema/CFG/CFG.h"
#include "mcsema/OS/OS.h"

DEFINE_int32(max_dataflow_analysis_iterations, 0,
             "Maximum number of iterations of a data flow pass to perform "
             "over the control-flow graph being lifted.");

DEFINE_bool(aggressive_dataflow_analysis, false,
            "Should data-flow analysis be conservative in their conclusions? "
            "If not then the analysis will be really aggressive and make a lot "
            "of assumptions about function call behavior.");

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

// Returns the ID for this binary. We prefix every basic block function added to
// a module with the ID of the binary, where the ID is a number that increments
// linearly.
static int GetBinaryId(llvm::Module *M) {
  for (auto i = 1; ; ++i) {
    std::string id = "mcsema_binary:" + std::to_string(i);
    if (!M->getNamedMetadata(id)) {
      M->getOrInsertNamedMetadata(id);
      return i;
    }
  }
  __builtin_unreachable();
}

}  // namespace

Translator::Translator(const Arch *arch_, llvm::Module *module_)
    : arch(arch_),
      module(module_),
      blocks(),
      functions(),
      symbols(),
      binary_id(GetBinaryId(module)),
      basic_block(FindFunction(module, "__mcsema_basic_block")),
      intrinsics(new IntrinsicTable(module)) {

  EnableDeferredInlining();
  IdentifyExistingSymbols();
}

namespace {

static void DisableInlining(llvm::Function *F) {
  F->removeFnAttr(llvm::Attribute::AlwaysInline);
  F->removeFnAttr(llvm::Attribute::InlineHint);
  F->addFnAttr(llvm::Attribute::NoInline);
}

}  // namespace

// Enable deferred inlining. The goal is to support better dead-store
// elimination for flags.
void Translator::EnableDeferredInlining(void) {
  if (!intrinsics->defer_inlining) return;
  DisableInlining(intrinsics->defer_inlining);

  for (auto U : intrinsics->defer_inlining->users()) {
    if (auto C = llvm::dyn_cast_or_null<llvm::CallInst>(U)) {
      auto B = C->getParent();
      auto F = B->getParent();
      DisableInlining(F);
    }
  }
}

// Find existing exported functions and variables. This is for the sake of
// linking functions of the same names across CFG files.
void Translator::IdentifyExistingSymbols(void) {
  for (auto &F : module->functions()) {
    std::string name = F.getName();
    if (module->getNamedMetadata(NamedSymbolMetaId(name))) {
      functions[name] = &F;
    }
  }

  for (auto &V : module->globals()) {
    std::string name = V.getName();
    if (module->getNamedMetadata(NamedSymbolMetaId(name))) {
      symbols[name] = &V;
    }
  }
}

namespace {

void InitBlockFuncAttributes(llvm::Function *BF, const llvm::Function *TF) {
  InitFunctionAttributes(BF);
  BF->setAttributes(TF->getAttributes());
  BF->arg_begin()->setName("state");
}

llvm::Function *GetBlockFunction(llvm::Module *M,
                                 const llvm::Function *TF,
                                 std::string name) {
  auto func_type = TF->getFunctionType();
  auto BF = llvm::dyn_cast<llvm::Function>(
      M->getOrInsertFunction(name, func_type));
  InitBlockFuncAttributes(BF, TF);
  BF->setLinkage(llvm::GlobalValue::PrivateLinkage);
  return BF;
}


}  // namespace

// Create functions for every block in the CFG.
void Translator::CreateFunctionsForBlocks(const cfg::Module *cfg) {
  std::set<uint64_t> indirect_blocks;
  for (const auto &block : cfg->indirect_blocks()) {
    indirect_blocks.insert(block.address());
  }

  for (const auto &block : cfg->blocks()) {
    auto &BF = blocks[block.address()];
    if (!BF) {
      std::stringstream ss;
      ss << "__lifted_block_" << binary_id << "_0x"
         << std::hex << block.address();

      BF = GetBlockFunction(module, basic_block, ss.str());

      // This block is externally visible so change its linkage and make a new
      // private block to which other blocks will refer.
      if (indirect_blocks.count(block.address())) {
        BF->setLinkage(llvm::GlobalValue::ExternalLinkage);

        ss << "_intern";
        auto BF_intern = GetBlockFunction(module, basic_block, ss.str());
        AddTerminatingTailCall(BF, BF_intern);
        BF = BF_intern;
      }
    }
  }
}

namespace {

// On Mac this strips off leading the underscore on symbol names.
//
// TODO(pag): This is really ugly and is probably incorrect. The expectation is
//            that the leading underscore will be re-added when this code is
//            compiled.
std::string CanonicalName(OSName os_name, const std::string &name) {
  if (kOSMacOSX == os_name && name.length() && '_' == name[0]) {
    return name.substr(1);
  } else {
    return name;
  }
}

}  // namespace

// Create functions for every function in the CFG.
void Translator::CreateExternalFunctions(const cfg::Module *cfg) {
  for (const auto &func : cfg->functions()) {
    if (!func.is_exported() && !func.is_imported()) continue;

    auto func_name = CanonicalName(arch->os_name, func.name());
    CHECK(!func_name.empty())
        << "Module contains unnamed function at address " << func.address();

    CHECK(!(func.is_exported() && func.is_imported()))
        << "Function " << func_name << " can't be imported and exported.";

    llvm::Function *&F = functions[func_name];
    if (!F) {
      F = GetBlockFunction(module, basic_block, func_name);

      // To get around some issues that `opt` has.
      F->addFnAttr(llvm::Attribute::NoBuiltin);
      F->addFnAttr(llvm::Attribute::OptimizeNone);
      F->addFnAttr(llvm::Attribute::NoInline);
      F->setLinkage(llvm::GlobalValue::ExternalWeakLinkage);
    }

    // Mark this symbol as external. We do this so that we can pick up on it
    // if we merge another CFG into this bitcode module.
    module->getOrInsertNamedMetadata(NamedSymbolMetaId(func_name));
  }
}

// Link together functions and basic blocks.
void Translator::LinkExternalFunctionsToBlocks(const cfg::Module *cfg) {
  for (const auto &func : cfg->functions()) {
    if (!func.is_exported() && !func.is_imported()) continue;
    if (!func.address()) continue;

    auto func_name = CanonicalName(arch->os_name, func.name());
    auto F = functions[func_name];
    auto &BF = blocks[func.address()];

    // In the case of an exported function, redirect the function's
    // implementation to a locally defined block.
    if (func.is_exported()) {

      CHECK(nullptr != BF)
          << "Exported function " << func_name << " has no address!";

      CHECK(F->isDeclaration())
          << "Function " << func_name << " is already defined!";

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
static std::vector<llvm::BasicBlock *> InitBlockFunction(
    llvm::Function *BF, const llvm::Function *TF, const cfg::Block &block) {
  llvm::ValueToValueMapTy var_map;
  auto targs = TF->arg_begin();
  auto bargs = BF->arg_begin();
  for (; targs != TF->arg_end(); ++targs, ++bargs) {
    var_map[&*targs] = &*bargs;
  }

  llvm::SmallVector<llvm::ReturnInst *, 1> returns;
  llvm::CloneFunctionInto(BF, TF, var_map, false, returns);

  InitBlockFuncAttributes(BF, TF);

  auto R = returns[0];
  R->removeFromParent();
  delete R;

  std::vector<llvm::BasicBlock *> instruction_blocks;
  instruction_blocks.reserve(block.instructions_size());
  instruction_blocks.push_back(&(BF->back()));
  for (const auto &instr : block.instructions()) {

    // Name the block according to the instruction's address.
    std::stringstream ss;
    ss << "0x" << std::hex << instr.address();

    // Create a block for this instruction.
    auto B = llvm::BasicBlock::Create(BF->getContext(), ss.str(), BF);
    instruction_blocks.push_back(B);
  }
  return instruction_blocks;
}

// Fall-through PC for a block.
static uint64_t FallThroughPC(const cfg::Block &block) {
  if (0 < block.instructions_size()) {
    const auto &instr = block.instructions(block.instructions_size() - 1);
    return instr.address() + instr.size();

  } else {
    LOG(ERROR) << "Using block address as fall-through address.";
    return block.address();
  }
}

}  // namespace

// Add a fall-through terminator to the block method just in case one is
// missing.
void Translator::TerminateBlockMethod(const cfg::Block &block,
                                      llvm::Function *BF) {
  auto &B = BF->back();
  if (B.getTerminator()) {
    return;
  }
  if (block.instructions_size()) {
    AddTerminatingTailCall(BF, GetLiftedBlockForPC(FallThroughPC(block)));
  } else {
    AddTerminatingTailCall(BF, intrinsics->error);
  }
}

// Lift code contained in blocks into the block methods.
void Translator::LiftBlocks(const cfg::Module *cfg) {
  llvm::legacy::FunctionPassManager FPM(module);
  FPM.add(llvm::createDeadCodeEliminationPass());
  FPM.add(llvm::createCFGSimplificationPass());
  FPM.add(llvm::createPromoteMemoryToRegisterPass());
  FPM.add(llvm::createReassociatePass());
  FPM.add(llvm::createInstructionCombiningPass());
  FPM.add(llvm::createDeadStoreEliminationPass());

  for (const auto &block : cfg->blocks()) {
    LOG_IF(WARNING, !block.instructions_size())
        << "Block at " << block.address() << " has no instructions!";

    auto BF = GetLiftedBlockForPC(block.address());
    if (!BF->isDeclaration()) {
      LOG(WARNING) << "Ignoring already lifted block at " << block.address();
      continue;
    }

    const auto instruction_blocks = InitBlockFunction(BF, basic_block, block);

    // Lift the instructions into the block in reverse order. This helps for
    // using the results of backward data-flow analyses.
    for (auto i = block.instructions_size(); i--; ) {
      const auto &instr = block.instructions(i);
      const auto bb = instruction_blocks[i + 1];
      LiftInstructionIntoBlock(block, instr, bb);
    }

    // Connect the internal blocks together with branches.
    if (instruction_blocks.size()) {
      for (auto i = 1; i < instruction_blocks.size(); ++i) {
        llvm::IRBuilder<> ir(instruction_blocks[i - 1]);
        ir.CreateBr(instruction_blocks[i]);
      }
    }

    TerminateBlockMethod(block, BF);

    // Perform simple, incremental optimizations on the block functions to
    // avoid OOMs.
    FPM.run(*BF);
  }
}

// Lift an instruction into a basic block. This does some minor sanity checks
// then dispatches to the arch-specific translator.
void Translator::LiftInstructionIntoBlock(
    const cfg::Block &block, const cfg::Instr &instr, llvm::BasicBlock *B) {

  CHECK(0 < instr.size())
      << "Can't decode zero-sized instruction at " << instr.address();

  CHECK(instr.size() == instr.bytes().length())
      << "Instruction size mismatch for instruction at " << instr.address();

  arch->LiftInstructionIntoBlock(*this, block, instr, B);
}

void Translator::LiftCFG(const cfg::Module *cfg) {
  blocks.clear();  // Just in case we call `LiftCFG` multiple times.
  CreateFunctionsForBlocks(cfg);
  CreateExternalFunctions(cfg);
  LinkExternalFunctionsToBlocks(cfg);
  AnalyzeCFG(cfg);
  LiftBlocks(cfg);
}

// Run an architecture-specific data-flow analysis on the module.
void Translator::AnalyzeCFG(const cfg::Module *cfg) {
  if (!FLAGS_max_dataflow_analysis_iterations) return;

  AnalysisWorkList wl;
  auto &analysis = arch->CFGAnalyzer();

  for (const auto &block : cfg->blocks()) {
    analysis.AddBlock(block);
  }

  for (const auto &func : cfg->functions()) {
    analysis.AddFunction(func);
  }

  analysis.InitWorkList(wl);
  for (auto i = 0;
       wl.size() && i < FLAGS_max_dataflow_analysis_iterations; ++i) {
    AnalysisWorkList next_wl;
    for (auto item : wl) {
      analysis.AnalyzeBlock(item, next_wl);
    }
    wl.swap(next_wl);
  }
  analysis.Finalize();
}

llvm::Function *Translator::GetLiftedBlockForPC(uintptr_t pc) const {
  auto F = blocks[pc];
  if (!F) {
    LOG(ERROR) << "Could not find lifted block for PC " << pc;
    F = intrinsics->undefined_block;
  }
  return F;
}

}  // namespace mcsema
