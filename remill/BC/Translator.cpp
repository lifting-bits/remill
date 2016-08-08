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
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Type.h>

#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/ValueMapper.h>

#include "remill/Arch/Arch.h"
#include "remill/BC/IntrinsicTable.h"
#include "remill/BC/Translator.h"
#include "remill/CFG/CFG.h"
#include "remill/OS/OS.h"

DEFINE_int32(max_dataflow_analysis_iterations, 0,
             "Maximum number of iterations of a data flow pass to perform "
             "over the control-flow graph being lifted.");

DEFINE_bool(aggressive_dataflow_analysis, false,
            "Should data-flow analysis be conservative in their conclusions? "
            "If not then the analysis will be really aggressive and make a "
            "lot of assumptions about function call behavior.");

namespace llvm {
class ReturnInst;
}  // namespace

namespace remill {

Translator::Translator(const Arch *arch_, llvm::Module *module_)
    : arch(arch_),
      module(module_),
      blocks(),
      functions(),
      symbols(),
      basic_block(FindFunction(module, "__remill_basic_block")),
      intrinsics(new IntrinsicTable(module)) {

  EnableDeferredInlining();
  IdentifyExistingSymbols();
}

namespace {

// Make sure that a function cannot be inlined by the optimizer. We use this
// as a way of ensuring that code that should be inlined later (i.e. invokes
// `__remill_defer_inlining`) definitely have the no-inline attributes set.
static void DisableInlining(llvm::Function *function) {
  function->removeFnAttr(llvm::Attribute::AlwaysInline);
  function->removeFnAttr(llvm::Attribute::InlineHint);
  function->addFnAttr(llvm::Attribute::NoInline);
}

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

// Initialize some attributes that are common to all newly created block
// functions. Also, give pretty names to the arguments of block functions.
void InitBlockFuncAttributes(llvm::Function *new_block_func,
                             const llvm::Function *template_func) {
  new_block_func->setAttributes(template_func->getAttributes());
  InitFunctionAttributes(new_block_func);
  auto args = new_block_func->arg_begin();
  (args++)->setName("state");
  (args++)->setName("memory");
  args->setName("pc");
}

llvm::Function *GetOrCreateBlockFunction(llvm::Module *module,
                                         const llvm::Function *template_func,
                                         std::string name) {
  auto func_type = template_func->getFunctionType();
  auto new_block_func = llvm::dyn_cast<llvm::Function>(
      module->getOrInsertFunction(name, func_type));
  InitBlockFuncAttributes(new_block_func, template_func);
  new_block_func->setVisibility(llvm::GlobalValue::HiddenVisibility);
  new_block_func->setLinkage(llvm::GlobalValue::PrivateLinkage);
  return new_block_func;
}

}  // namespace

// Enable deferred inlining. The goal is to support better dead-store
// elimination for flags.
void Translator::EnableDeferredInlining(void) {
  if (!intrinsics->defer_inlining) return;
  DisableInlining(intrinsics->defer_inlining);

  for (auto callers : intrinsics->defer_inlining->users()) {
    if (auto call_instr = llvm::dyn_cast_or_null<llvm::CallInst>(callers)) {
      auto bb = call_instr->getParent();
      auto caller = bb->getParent();
      DisableInlining(caller);
    }
  }
}

// Find existing exported functions and variables. This is for the sake of
// linking functions of the same names across CFG files.
void Translator::IdentifyExistingSymbols(void) {
  for (llvm::Function &function : module->functions()) {
    std::string name = function.getName();
    functions[name] = &function;
  }

  for (llvm::GlobalVariable &value : module->globals()) {
    std::string name = value.getName();
    symbols[name] = &value;
  }
}

// Create functions for every block in the CFG.
void Translator::CreateFunctionsForExternals(const cfg::Module *cfg) {
  for (const auto &func : cfg->functions()) {
    CHECK(!func.name().empty())
        << "Module contains unnamed exported function at address "
        << func.address() << ".";

    auto func_name = CanonicalName(arch->os_name, func.name());
    auto &extern_func = functions[func_name];

    if (!extern_func) {

      // Function is exported; what we need to do is expose the function name,
      // create a new states and memory objects, and then "enter" remill code.
      //
      // TODO(pag): What about returns from native-to-Remill-lifted code? This
      //            is mostly relevant for compiling lifted code.
      if (func.is_exported()) {
        CHECK(!func.is_imported())
            << "Function " << func_name
            << " cannot be both imported and exported.";

        extern_func = CreateExportedFunction(func_name, func.address());

      // Function is imported; create a detach point for it.
      } else if (func.is_imported()) {
        extern_func = CreateImportedFunction(func_name, func.address());

        if (func.address()) {
          blocks[func.address()] = extern_func;
        } else {
          LOG(WARNING)
              << "Imported function " << func_name << " has no address; "
              << "lifted code will have no way of reaching it.";
        }
      }
    }
  }
}

// Create functions for every block in the CFG.
void Translator::CreateFunctionsForBlocks(const cfg::Module *cfg) {
  std::set<uint64_t> indirect_blocks;
  for (const auto &block : cfg->indirect_blocks()) {
    indirect_blocks.insert(block.address());
  }

  for (const auto &block : cfg->blocks()) {
    auto &block_func = blocks[block.address()];
    if (!block_func) {
      std::stringstream ss;
      ss << "__remill_sub_" << std::hex << block.address();

      block_func = GetOrCreateBlockFunction(module, basic_block, ss.str());

      // This block is externally visible so change its linkage and make a new
      // private block to which other blocks will refer.
      if (indirect_blocks.count(block.address())) {
        block_func->setVisibility(llvm::GlobalValue::DefaultVisibility);
        block_func->setLinkage(llvm::GlobalValue::ExternalLinkage);
      }
    }
  }
}

namespace {

static llvm::Function *CreateExternFunc(llvm::Module *module,
                                        const std::string &name) {
  auto unknown_func_type = llvm::FunctionType::get(
      llvm::Type::getVoidTy(module->getContext()), false);

  auto extern_func = llvm::Function::Create(
      unknown_func_type,
      llvm::GlobalValue::ExternalLinkage,
      name);

  extern_func->addFnAttr(llvm::Attribute::NoBuiltin);

  return extern_func;
}

}  // namespace

// Create functions for every exported function in the CFG.
//
// TODO(pag): Perhaps what this shouldn't be handled here at all.
llvm::Function *Translator::CreateExportedFunction(
    const std::string &name, uintptr_t addr) {

  LOG(INFO)
      << "Ignoring exported function " << name << " at " << addr
      << " until more decisions are made.";

  return nullptr;
}

// Create functions for every imported function in the CFG.
llvm::Function *Translator::CreateImportedFunction(
    const std::string &name, uintptr_t addr) {

  CHECK(!name.empty())
      << "Module contains unnamed imported function at address "
      << addr << ".";

  auto imported_func = CreateExternFunc(module, name);

  // Create a block function
  std::stringstream ss;
  ss << "__remill_detach_" << name;
  auto func = GetOrCreateBlockFunction(module, basic_block, ss.str());
  llvm::IRBuilder<> ir(llvm::BasicBlock::Create(
      func->getContext(), name, func));

  auto pc_addr = ir.CreateLoad(FindVarInFunction(func, "PC"));
  auto pc_type = pc_addr->getType()->getContainedType(0);
  auto native_pc = ir.CreatePtrToInt(imported_func, pc_type, "native_addr");
  ir.CreateStore(native_pc, pc_addr);
  AddTerminatingTailCall(func, intrinsics->detach);

  return func;
}

// Link together functions and basic blocks.
void Translator::LinkExternalFunctionsToBlocks(const cfg::Module *cfg) {
  for (const auto &func : cfg->functions()) {
    if (!func.is_exported() && !func.is_imported()) continue;
    if (!func.address()) continue;

    std::stringstream ss;
    ss << "__remill_extern_";
    ss << CanonicalName(arch->os_name, func.name());

    auto func_name = ss.str();
    auto extern_func = functions[func_name];
    auto &block_impl_func = blocks[func.address()];

    // In the case of an exported function, redirect the function's
    // implementation to a locally defined block.
    if (func.is_exported()) {

      CHECK(nullptr != block_impl_func)
          << "Exported function " << func_name << " has no address!";

      CHECK(extern_func->isDeclaration())
          << "Function " << func_name << " is already defined!";

      AddTerminatingTailCall(extern_func, block_impl_func);

    // In the case of ELF binaries, we tend to see a call to something like
    // `malloc@plt` that is responsible for finding and invoking the actual
    // `malloc` implementation. In this case, we want to treat the `malloc@plt`
    // block address as synonymous with the function.
    //
    // TODO(pag): What about versioned ELF symbols?
    } else if (func.is_imported()) {
      if (!block_impl_func) {
        block_impl_func = extern_func;
      } else {
        AddTerminatingTailCall(block_impl_func, extern_func);
      }
    }
  }
}

namespace {

// Clone the block method template `TF` into a specific method `BF` that
// will contain lifted code.
//
// This will create one basic block per instruction-to-lift, where these
// instructions are listed out in `block`.
static std::vector<llvm::BasicBlock *> InitBlockFunction(
    llvm::Function *block_func,
    const llvm::Function *template_func,
    const cfg::Block &block) {

  llvm::ValueToValueMapTy var_map;
  auto targs = template_func->arg_begin();
  auto bargs = block_func->arg_begin();
  for (; targs != template_func->arg_end(); ++targs, ++bargs) {
    var_map[&*targs] = &*bargs;
  }

  llvm::SmallVector<llvm::ReturnInst *, 1> return_instrs;
  llvm::CloneFunctionInto(
      block_func, template_func, var_map, false, return_instrs);

  InitBlockFuncAttributes(block_func, template_func);

  // We're cloning the function, and we want to keep all of the variables
  // defined in the function, but it has an implicit return that we need
  // to remove so that we can add instructions at the end.
  auto return_instr = return_instrs[0];
  return_instr->removeFromParent();
  delete return_instr;

  std::vector<llvm::BasicBlock *> instruction_blocks;
  instruction_blocks.reserve(block.instructions_size());
  instruction_blocks.push_back(&(block_func->back()));
  for (const auto &instr : block.instructions()) {

    // Name the block according to the instruction's address.
    std::stringstream ss;
    ss << "0x" << std::hex << instr.address();

    // Create a block for this instruction.
    auto basic_block = llvm::BasicBlock::Create(
        block_func->getContext(), ss.str(), block_func);
    instruction_blocks.push_back(basic_block);
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
void Translator::TryTerminateBlockMethod(const cfg::Block &block,
                                         llvm::Function *BF) {
  auto &B = BF->back();
  if (B.getTerminator()) {
    return;
  }
  if (block.instructions_size()) {
    AddTerminatingTailCall(BF, GetLiftedBlockForPC(FallThroughPC(block)));
  } else {
    AddTerminatingTailCall(BF, intrinsics->detach);
  }
}

// Lift code contained in blocks into the block methods.
void Translator::LiftBlocks(const cfg::Module *cfg) {
  llvm::legacy::FunctionPassManager func_pass_manager(module);
  func_pass_manager.add(llvm::createDeadCodeEliminationPass());
  func_pass_manager.add(llvm::createCFGSimplificationPass());
  func_pass_manager.add(llvm::createPromoteMemoryToRegisterPass());
  func_pass_manager.add(llvm::createReassociatePass());
  func_pass_manager.add(llvm::createInstructionCombiningPass());
  func_pass_manager.add(llvm::createDeadStoreEliminationPass());

  for (const auto &block : cfg->blocks()) {
    LOG_IF(WARNING, !block.instructions_size())
        << "Block at " << block.address() << " has no instructions!";

    auto block_func = GetLiftedBlockForPC(block.address());
    if (!block_func->isDeclaration()) {
      LOG(WARNING) << "Ignoring already lifted block at " << block.address();
      continue;
    }

    const auto instruction_blocks = InitBlockFunction(
        block_func, basic_block, block);

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

    // Terminate blocks that end in a fall-through to their next blocks. This
    // only happens if the arch-specific code didn't already add a terminator.
    // The arch-specific code is in the best position to know when and what
    // type of terminators are needed.
    TryTerminateBlockMethod(block, block_func);

    // Perform simple, incremental optimizations on the block functions to
    // avoid OOMs.
    func_pass_manager.run(*block_func);
  }
}

// Lift an instruction into a basic block. This does some minor sanity checks
// then dispatches to the arch-specific translator.
void Translator::LiftInstructionIntoBlock(
    const cfg::Block &block, const cfg::Instr &instr,
    llvm::BasicBlock *instr_block) {

  CHECK(0 < instr.size())
      << "Can't decode zero-sized instruction at " << instr.address();

  CHECK(instr.size() == instr.bytes().length())
      << "Instruction size mismatch for instruction at " << instr.address();

  arch->LiftInstructionIntoBlock(*this, block, instr, instr_block);
}

// Lift the control-flow graph specified by `cfg` into this bitcode module.
void Translator::LiftCFG(const cfg::Module *cfg) {
  blocks.clear();  // Just in case we call `LiftCFG` multiple times.

  CreateFunctionsForExternals(cfg);
  CreateFunctionsForBlocks(cfg);
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
  auto block_func = blocks[pc];

  // Not being able the find the CFG for a block is not a fatal error, it could
  // be that we don't know or want to know all the things up-front but instead
  // want to resolve them lazily (in a runtime).
  if (!block_func) {
    LOG(ERROR) << "Could not find lifted block for PC " << pc;
    block_func = intrinsics->detach;
  }
  return block_func;
}

}  // namespace remill
