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

// Create functions for every block in the CFG.
void Translator::CreateBlocks(const cfg::Module *cfg) {
  std::set<uint64_t> indirect_blocks;
  for (const auto &block : cfg->indirect_blocks()) {
    indirect_blocks.insert(block.address());
  }

  auto block_type = basic_block->getFunctionType();
  for (const auto &block : cfg->blocks()) {
    auto &BF = blocks[block.address()];
    if (!BF) {
      std::stringstream ss;
      ss << "__lifted_block_" << binary_id << "_0x"
         << std::hex << block.address();
      BF = llvm::dyn_cast<llvm::Function>(
          module->getOrInsertFunction(ss.str(), block_type));

      InitFunctionAttributes(BF);

      // There doesn't seem to be any way for indirect control flows to reach
      // this block, so we'll mark it as internal to the module. This improves
      // LLVM's ability to optimize it.
      if (!indirect_blocks.count(block.address())) {
        BF->setLinkage(llvm::GlobalValue::PrivateLinkage);

      // This should enable some inlining optimizations when they make sense
      // to the compiler, and should also make the symbols visible externally.
      } else {
        BF->setLinkage(llvm::GlobalValue::ExternalLinkage);

        // Create a new block, where the original entry block, correctly named,
        // directly jumps to this internal block. Hopefully there will be
        // situations where there are internal jumps to this externally visible
        // block and we want to enable inlining optimizations in these cases.
        ss << "_intern";
        auto BF_intern = llvm::dyn_cast<llvm::Function>(
            module->getOrInsertFunction(ss.str(), block_type));
        BF_intern->setLinkage(llvm::GlobalValue::PrivateLinkage);

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
void Translator::CreateFunctions(const cfg::Module *cfg) {
  auto func_type = basic_block->getFunctionType();

  for (const auto &func : cfg->functions()) {
    if (!func.is_exported() && !func.is_imported()) continue;

    auto func_name = CanonicalName(arch->os_name, func.name());
    CHECK(!func_name.empty())
        << "Module contains unnamed function at address " << func.address();

    CHECK(!(func.is_exported() && func.is_imported()))
        << "Function " << func_name << " can't be imported and exported.";

    llvm::Function *&F = functions[func_name];
    if (!F) {
      F = llvm::dyn_cast<llvm::Function>(
          module->getOrInsertFunction(func_name, func_type));

      InitFunctionAttributes(F);

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
void Translator::LinkFunctionsToBlocks(const cfg::Module *cfg) {
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

void Translator::LiftBlockIntoMethod(const cfg::Block &block,
                                     llvm::Function *BF) {
  auto num_lifted = 0;
  for (const auto &instr : block.instructions()) {
    CHECK(0 < instr.size())
        << "Can't decode zero-sized instruction at " << instr.address();

    CHECK(instr.size() == instr.bytes().length())
        << "Instruction size mismatch for instruction at " << instr.address();

    num_lifted += 1;
    switch (LiftInstructionIntoBlock(block, instr, BF)) {
      case kLiftNextInstruction:
        break;

      case kTerminateBlock:
        LOG_IF(WARNING, num_lifted < block.instructions_size())
            << "Did not lift all instructions from block " << block.address();
        return;
    }
  }
  LOG_IF(WARNING, num_lifted < block.instructions_size())
      << "Did not lift all instructions from block " << block.address();
}

// Create a basic block for an instruction.
InstructionLiftAction Translator::LiftInstructionIntoBlock(
    const cfg::Block &block, const cfg::Instr &instr,
    llvm::Function *BF) {

  // Name the block according to the instruction's address.
  std::stringstream ss;
  ss << "0x" << std::hex << instr.address();

  // Create a block for this instruction.
  auto P = &(BF->back());
  auto B = llvm::BasicBlock::Create(BF->getContext(), ss.str(), BF);

  // Connect the block to its predecessor.
  llvm::IRBuilder<> ir(P);
  ir.CreateBr(B);

  return arch->LiftInstructionIntoBlock(*this, block, instr, B);
}

void Translator::LiftCFG(const cfg::Module *cfg) {
  blocks.clear();  // Just in case we call `LiftCFG` multiple times.
  CreateBlocks(cfg);
  CreateFunctions(cfg);
  LinkFunctionsToBlocks(cfg);
  AnalyzeCFG(cfg);
  LiftBlocks(cfg);
  OptimizeModule();
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
}

llvm::Function *Translator::GetLiftedBlockForPC(uintptr_t pc) const {
  auto F = blocks[pc];
  if (!F) {
    LOG(ERROR) << "Could not find lifted block for PC " << pc;
    F = intrinsics->undefined_block;
  }
  return F;
}

namespace {

// Replace all uses of a specific intrinsic with an undefined value.
static void ReplaceIntrinsic(llvm::Function *F, unsigned N) {
  if (!F) return;

  std::vector<llvm::CallInst *> Cs;
  for (auto U : F->users()) {
    if (auto C = llvm::dyn_cast<llvm::CallInst>(U)) {
      Cs.push_back(C);
    }
  }

  auto Undef = llvm::UndefValue::get(llvm::Type::getIntNTy(F->getContext(), N));
  for (auto C : Cs) {
    C->replaceAllUsesWith(Undef);
    C->removeFromParent();
    delete C;
  }
}

}  // namespace

// Remove calls to the undefined intrinsics. The goal here is to improve dead
// store elimination by peppering the instruction semantics with assignments
// to the return values of special `__mcsema_undefined_*` intrinsics. It's hard
// to reliably produce an `undef` LLVM value from C/C++, so we use our trick
// of declaring (but never defining) a special "intrinsic" and then we replace
// all such uses with `undef` values.
void Translator::OptimizeModule(void) {
  ReplaceIntrinsic(intrinsics->undefined_bool, 1);
  ReplaceIntrinsic(intrinsics->undefined_8, 8);
  ReplaceIntrinsic(intrinsics->undefined_16, 16);
  ReplaceIntrinsic(intrinsics->undefined_32, 32);
  ReplaceIntrinsic(intrinsics->undefined_64, 64);
}

}  // namespace mcsema
