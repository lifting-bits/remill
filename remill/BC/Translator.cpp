/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <functional>
#include <ios>
#include <set>
#include <string>
#include <sstream>
#include <vector>

#include <llvm/ADT/SmallVector.h>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/Verifier.h>

#include <llvm/Support/raw_ostream.h>

#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/ValueMapper.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/AssemblyWriter.h"
#include "remill/BC/IntrinsicTable.h"
#include "remill/BC/Translator.h"
#include "remill/BC/Util.h"
#include "remill/CFG/CFG.h"
#include "remill/OS/OS.h"

DECLARE_bool(define_unimplemented);

namespace llvm {
class ReturnInst;
}  // namespace llvm

namespace remill {
namespace {

// Initialize some attributes that are common to all newly created block
// functions. Also, give pretty names to the arguments of block functions.
static void InitBlockFunctionAttributes(llvm::Function *block_func) {

  block_func->setLinkage(llvm::GlobalValue::PrivateLinkage);
  block_func->setVisibility(llvm::GlobalValue::DefaultVisibility);

  auto args = block_func->arg_begin();
  (args++)->setName("memory");
  (args++)->setName("state");
  args->setName("pc");

}

// These variables must always be defined within `__remill_basic_block`.
static bool BlockHasSpecialVars(llvm::Function *basic_block) {
  return FindVarInFunction(basic_block, "STATE", true) &&
         FindVarInFunction(basic_block, "MEMORY", true) &&
         FindVarInFunction(basic_block, "PC", true) &&
         FindVarInFunction(basic_block, "NEXT_PC", true) &&
         FindVarInFunction(basic_block, "BRANCH_TAKEN", true);
}

// Clang isn't guaranteed to play nice and name the LLVM values within the
// `__remill_basic_block` instrinsic with the same names as we find in the
// C++ definition of that function. However, we compile that function with
// debug information, and so we will try to recover the variables names for
// later lookup.
static void FixupBasicBlockVariables(llvm::Function *basic_block) {
  if (BlockHasSpecialVars(basic_block)) {
    return;
  }

  for (auto &block : *basic_block) {
    for (auto &inst : block) {
      if (auto decl_inst = llvm::dyn_cast<llvm::DbgDeclareInst>(&inst)) {
        auto addr = decl_inst->getAddress();
        addr->setName(decl_inst->getVariable()->getName());
      }
    }
  }

  CHECK(BlockHasSpecialVars(basic_block))
      << "Unable to locate required variables in `__remill_basic_block`.";
}

}  // namespace

Translator::Translator(const Arch *arch_, llvm::Module *module_,
                       AssemblyWriter *src_)
    : arch(arch_),
      module(module_),
      asm_source_writer(src_),
      blocks(),
      indirect_blocks(),
      exported_blocks(),
      basic_block(FindFunction(module, "__remill_basic_block")),
      word_type(llvm::Type::getIntNTy(
          module->getContext(), arch->address_size)),
      intrinsics(new IntrinsicTable(module)) {

  CHECK(nullptr != basic_block)
      << "Unable to find __remill_basic_block.";

  FixupBasicBlockVariables(basic_block);
  EnableDeferredInlining();
  InitFunctionAttributes(basic_block);
  InitBlockFunctionAttributes(basic_block);
}

Translator::~Translator(void) {
  delete intrinsics;
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
//
// TODO(pag): `main` on macOS.
//
// TODO(pag): AMD64 C++ name mangling.
//
// TODO(pag): What about on Windows?
static std::string CanonicalName(OSName os_name, const std::string &name) {
  (void) os_name;
  return name;
//  if (kOSmacOS == os_name && name.length() && '_' == name[0]) {
//    return name.substr(1);
//  } else {
//    return name;
//  }
}

// Pull the `name` out of a `NamedBlock`.
static std::string GetSubroutineName(llvm::ConstantStruct *exported_block) {
  auto name_gep = exported_block->getOperand(0);
  auto name_var = llvm::dyn_cast<llvm::GlobalVariable>(
      name_gep->getOperand(0));
  auto name_arr = llvm::dyn_cast<llvm::ConstantDataArray>(
      name_var->getOperand(0));
  return name_arr->getAsCString();
}

// Create an external function given a function name. These will be used to
// reference imports and exports.
static llvm::Function *CreateExternalFunction(llvm::Module *module,
                                              const std::string &name) {
  auto unknown_func_type = llvm::FunctionType::get(
      llvm::Type::getVoidTy(module->getContext()), false);
  auto func = llvm::dyn_cast<llvm::Function>(
      module->getOrInsertFunction(name, unknown_func_type));

  // Don't want these to conflict with things like `__builtin_sin`.
  func->addFnAttr(llvm::Attribute::NoBuiltin);

  return func;
}

static void RemoveDebugInfo(llvm::Function *block_func) {
  block_func->clearMetadata();

  std::vector<llvm::Instruction *> to_remove;
  for (auto &bb : *block_func) {
    for (auto &inst : bb) {
      if (llvm::isa<llvm::CallInst>(inst)) {
        to_remove.push_back(&inst);
      } else {
        inst.setDebugLoc(llvm::DebugLoc());
      }
    }
  }

  for (auto call_inst : to_remove) {
    call_inst->eraseFromParent();
  }
}

// Clone the block method template `TF` into a specific method `BF` that
// will contain lifted code.
static void AddBlockInitializationCode(llvm::Function *block_func,
                                       llvm::Function *template_func) {

  llvm::ValueToValueMapTy var_map;
  var_map[template_func] = block_func;

  auto block_args = block_func->arg_begin();
  for (const llvm::Argument &arg : template_func->args()) {
    var_map[&arg] = &*block_args;
    ++block_args;
  }

  llvm::SmallVector<llvm::ReturnInst *, 1> return_instrs;
  llvm::CloneFunctionInto(
      block_func, template_func, var_map, false, return_instrs);

  RemoveDebugInfo(block_func);

  // We're cloning the function, and we want to keep all of the variables
  // defined in the function, but it has an implicit return that we need
  // to remove so that we can add instructions at the end.
  return_instrs[0]->eraseFromParent();
}

}  // namespace

// Enable deferred inlining. The goal is to support better dead-store
// elimination for flags.
void Translator::EnableDeferredInlining(void) {
  DisableInlining(intrinsics->defer_inlining);

  for (auto callers : intrinsics->defer_inlining->users()) {
    if (auto call_instr = llvm::dyn_cast_or_null<llvm::CallInst>(callers)) {
      auto bb = call_instr->getParent();
      auto caller = bb->getParent();
      DisableInlining(caller);
    }
  }
}

// Find existing exported functions. This is for the sake of linking functions
// of the same names across CFG files.
std::map<std::string, llvm::Function *> Translator::GetNamedBlocks(
    const char *table_name) {
  std::map<std::string, llvm::Function *> table;
  auto table_var = module->getGlobalVariable(table_name);
  auto init = table_var->getInitializer();
  if (llvm::isa<llvm::ConstantAggregateZero>(init)) {
    return table;
  }
  auto entries = llvm::dyn_cast<llvm::ConstantArray>(init);
  DLOG(INFO)
      << "Exported block table has " << entries->getNumOperands()
      << " entries.";

  for (const auto &entry : entries->operands()) {

    if (llvm::isa<llvm::ConstantAggregateZero>(entry)) {
      continue;
    }

    // Note: Each `entry` has the following type:
    //    struct NamedBlock final {
    //      const char * const name;
    //      void (* const lifted_func)(Memory &, State &, addr_t);
    //      void (* const native_func)(void);
    //    };
    auto exported_block = llvm::dyn_cast<llvm::ConstantStruct>(entry.get());
    auto func_name = GetSubroutineName(exported_block);
    auto lifted_func = llvm::dyn_cast<llvm::Function>(
        exported_block->getOperand(1));
    table[func_name] = lifted_func;
  }

  return table;
}

// Recreate a global table of named blocks.
void Translator::SetNamedBlocks(
    std::map<std::string, llvm::Function *> &table,
    const char *table_name) {
  auto table_var = module->getGlobalVariable(table_name);

  // Yank out the type of the table and of its entries.
  llvm::ArrayType *array_type = llvm::dyn_cast<llvm::ArrayType>(
      table_var->getValueType());
  llvm::StructType *entry_type = llvm::dyn_cast<llvm::StructType>(
      array_type->getArrayElementType());

  auto new_array_type = llvm::ArrayType::get(
      entry_type, table.size() + 1);

  // Replace the old one.
  table_var->eraseFromParent();
  table_var = new llvm::GlobalVariable(
        *module,
        new_array_type,
        true,
        llvm::GlobalValue::ExternalLinkage,
        nullptr,
        table_name);

  auto &context = module->getContext();
  auto char_type = llvm::Type::getInt8Ty(context);
  auto int_type = llvm::Type::getInt32Ty(context);
  auto zero = llvm::ConstantInt::get(int_type, 0);

  std::vector<llvm::Constant *> entries;

  // Need to make a GEP that gets the address of the first character in a string
  // with a function's name. First index is going through the global variable
  // pointer, second is to get the first character.
  std::vector<llvm::Value *> index_list;
  index_list.push_back(zero);
  index_list.push_back(zero);

  for (const auto &kv : table) {
    auto block_func = kv.second;

    // We create a kind of dummy function for every imported/exported symbol.
    // The hope is that this will make it easier for downstream tools to use
    // this table.
    auto extern_func = CreateExternalFunction(module, kv.first);

    // We want to avoid making the same function name string over and over
    // again so we'll make a variable with the name of the string itself and
    // just never use this special variable naming scheme for anything else.
    std::stringstream ss;
    ss << "__remill_string_" << kv.first;
    auto str_type = llvm::ArrayType::get(char_type, kv.first.size() + 1);
    auto block_name_const = module->getOrInsertGlobal(ss.str(), str_type);
    auto block_name_var = llvm::dyn_cast<llvm::GlobalVariable>(
        block_name_const);

    if (!block_name_var->hasInitializer()) {
      auto block_name = llvm::ConstantDataArray::getString(
          context, kv.first, true);
      block_name_var->setInitializer(block_name);
    }

    // Note: Each entry has the following type:
    //    struct NamedBlock final {
    //      const char * const name;
    //      void (* const lifted_func)(Memory &, State &, addr_t);
    //      void (* const native_func)(void);
    //    };
    entries.push_back(llvm::ConstantStruct::get(
        entry_type,
        llvm::ConstantExpr::getGetElementPtr(
            str_type, block_name_var, index_list),
        block_func,
        extern_func,
        nullptr));
  }

  entries.push_back(llvm::ConstantAggregateZero::get(entry_type));
  table_var->setInitializer(llvm::ConstantArray::get(new_array_type, entries));
}

// Identify the already lifted basic blocks.
void Translator::GetIndirectBlocks(void) {
  auto table_var = module->getGlobalVariable("__remill_indirect_blocks");
  auto init = table_var->getInitializer();

  if (llvm::isa<llvm::ConstantAggregateZero>(init)) {
    return;
  }
  auto entries = llvm::dyn_cast<llvm::ConstantArray>(init);
  DLOG(INFO)
      << "Indirect block table has " << entries->getNumOperands()
      << " entries.";

  for (const auto &entry : entries->operands()) {
    if (llvm::isa<llvm::ConstantAggregateZero>(entry)) {
      continue;
    }
    // Note: Each `entry` has the following type:
    //    struct IndirectBlock final {
    //      const addr_t lifted_address;
    //      void (* const lifted_func)(Memory &, State &, addr_t);
    //    };
    auto indirect_block = llvm::dyn_cast<llvm::ConstantStruct>(entry.get());
    auto block_addr = llvm::dyn_cast<llvm::ConstantInt>(
        indirect_block->getOperand(0))->getZExtValue();
    auto lifted_func = llvm::dyn_cast<llvm::Function>(
        indirect_block->getOperand(1));

    blocks[block_addr] = lifted_func;
    indirect_blocks[block_addr] = lifted_func;
  }
}

// Recreate the global table of indirectly addressible blocks.
void Translator::SetIndirectBlocks(void) {
  if (indirect_blocks.empty()) {
    return;
  }

  auto table_var = module->getGlobalVariable("__remill_indirect_blocks");

  // Yank out the type of the table and of its entries.
  llvm::ArrayType *array_type = llvm::dyn_cast<llvm::ArrayType>(
      table_var->getValueType());
  llvm::StructType *entry_type = llvm::dyn_cast<llvm::StructType>(
      array_type->getArrayElementType());

  auto new_array_type = llvm::ArrayType::get(
      entry_type, indirect_blocks.size() + 1);

  // Replace the old one.
  table_var->eraseFromParent();
  table_var = new llvm::GlobalVariable(
        *module,
        new_array_type,
        true,
        llvm::GlobalValue::ExternalLinkage,
        nullptr,
        "__remill_indirect_blocks");

  auto &context = module->getContext();
  auto long_type = llvm::Type::getInt64Ty(context);

  std::vector<llvm::Constant *> entries;
  for (const auto &kv : indirect_blocks) {
    // Note: Each entry has the following type:
    //    struct IndirectBlock final {
    //      const uint64_t lifted_address;
    //      void (* const lifted_func)(State &, Memory &, addr_t);
    //    };

    entries.push_back(llvm::ConstantStruct::get(
        entry_type,
        llvm::ConstantInt::get(long_type, kv.first),
        kv.second,
        nullptr));
  }

  entries.push_back(llvm::ConstantAggregateZero::get(entry_type));
  table_var->setInitializer(llvm::ConstantArray::get(new_array_type, entries));
}

// Create functions for every exported function in the CFG.
void Translator::CreateNamedBlocks(const cfg::Module *cfg) {
  for (const auto &func : cfg->named_blocks()) {

    CHECK(func.name().size())
        << "Unnamed block at address " << std::hex << func.address();

    auto func_name = CanonicalName(arch->os_name, func.name());
    CHECK(func.address())
        << "Named block " << func_name << " has no address.";

    auto is_imported = cfg::Visibility::IMPORTED == func.visibility();
    auto &indirect_block = indirect_blocks[func.address()];
    auto &named_block = (is_imported ? imported_blocks :
                                       exported_blocks)[func_name];

    if (named_block && indirect_block) {
      CHECK(named_block == indirect_block)
          << "Both " << named_block->getName().str() << " and "
          << indirect_block->getName().str() << " implement " << func_name
          << " at address " << std::hex << func.address() << ".";

    } else if (!named_block && indirect_block) {
      named_block = indirect_block;

    } else if (named_block && !indirect_block) {
      indirect_block = named_block;
      blocks[func.address()] = indirect_block;

    } else {
      named_block = GetOrCreateBlock(func.address());
      indirect_block = named_block;
      blocks[func.address()] = indirect_block;
    }

    auto impl_name = named_block->getName().str();

    if (is_imported && FLAGS_define_unimplemented) {
      if (named_block->isDeclaration()) {
        AddTerminatingTailCall(named_block, intrinsics->detach);

        if (asm_source_writer) {
          asm_source_writer->WriteBlock(named_block);
        }

        DLOG(INFO)
            << "Imported function " << func_name << " is implemented by "
            << impl_name << ".";

      } else {
        auto term = named_block->back().getTerminatingMustTailCall();
        CHECK(term && intrinsics->detach != term->getCalledFunction())
            << "Imported function " << func_name << " implemented by "
            << impl_name << " does not end in a tail call to __remill_detach.";
      }
    } else {
      DLOG(INFO)
          << "Exported function " << func_name << " is implemented by "
          << impl_name << ".";
    }
  }
}

// Create a function for a single block.
llvm::Function *Translator::GetOrCreateBlock(uint64_t addr) {
  auto &block_func = blocks[addr];
  if (!block_func) {
    std::stringstream ss;
    ss << "__remill_sub_" << std::hex << addr;
    auto func_name = ss.str();

    auto func_type = basic_block->getFunctionType();
    block_func = llvm::dyn_cast<llvm::Function>(
        module->getOrInsertFunction(func_name, func_type));

    // Initialize the generic attributes, but change the linkage into
    // external until the block is implemented.
    block_func->copyAttributesFrom(basic_block);
    block_func->setLinkage(llvm::GlobalValue::ExternalLinkage);

    DLOG(INFO)
        << "Created function " << func_name
        << " for block at " << std::hex << addr << ".";
  }
  return block_func;
}

// Create a function for a single block. This block appears as the target
// of some control-flow instruction. Make sure that it has a default detach-
// based implementation.
llvm::Function *Translator::GetOrCreateTargetBlock(uint64_t address) {
  auto block_func = GetOrCreateBlock(address);
  if (block_func->isDeclaration() && FLAGS_define_unimplemented) {
    AddTerminatingTailCall(block_func, intrinsics->detach);
    if (asm_source_writer) {
      asm_source_writer->WriteBlock(block_func);
    }
  }
  return block_func;
}

// Create functions for every block in the CFG. We do this before lifting so
// that we can easily reference those blocks.
void Translator::CreateBlocks(const cfg::Module *cfg_module) {
  for (const auto &cfg_block : cfg_module->blocks()) {
    CHECK(cfg_block.instructions_size())
        << "Block at address " << std::hex << cfg_block.address()
        << " has no instructions.";

    auto block_func = GetOrCreateBlock(cfg_block.address());

    // For now, mark the block as external linkage if we don't have an
    // implementation of it. When we implement it, we can change it
    // to have internal linkage.
    if (block_func->isDeclaration()) {
      block_func->setLinkage(llvm::GlobalValue::ExternalLinkage);
    }

    if (cfg_block.is_addressable()) {
      auto &indirect_block_func = indirect_blocks[cfg_block.address()];

      CHECK(block_func == indirect_block_func || !indirect_block_func)
          << "Multiply defined addressable cfg_block at "
          << std::hex << cfg_block.address() << ".";

      indirect_block_func = block_func;
    }
  }

  for (const auto cfg_ref_block_addr : cfg_module->referenced_blocks()) {
    auto block_func = GetOrCreateTargetBlock(cfg_ref_block_addr);
    if (block_func->isDeclaration()) {
      block_func->setLinkage(llvm::GlobalValue::ExternalLinkage);
    }
  }
}

// Lift the control-flow graph specified by `cfg` into this bitcode module.
void Translator::LiftCFG(const cfg::Module *cfg_module) {
  blocks.clear();
  indirect_blocks.clear();

  exported_blocks = GetNamedBlocks("__remill_exported_blocks");
  imported_blocks = GetNamedBlocks("__remill_imported_blocks");

  GetIndirectBlocks();
  CreateNamedBlocks(cfg_module);
  CreateBlocks(cfg_module);

  // Sanity check to make sure conflicting versions of a named block don't
  // appear.
  for (const auto &entry : exported_blocks) {
    CHECK(!imported_blocks.count(entry.first))
        << "Subroutine " << entry.first << " cannot be both exported "
        << "and imported.";
  }

  SetNamedBlocks(exported_blocks, "__remill_exported_blocks");
  SetNamedBlocks(imported_blocks, "__remill_imported_blocks");
  SetIndirectBlocks();

  LiftBlocks(cfg_module);
}

// Lift code contained in blocks into the block methods.
void Translator::LiftBlocks(const cfg::Module *cfg_module) {
  llvm::legacy::FunctionPassManager func_pass_manager(module);
  func_pass_manager.add(llvm::createDeadCodeEliminationPass());
  func_pass_manager.add(llvm::createCFGSimplificationPass());
  func_pass_manager.add(llvm::createPromoteMemoryToRegisterPass());
  func_pass_manager.add(llvm::createReassociatePass());
  func_pass_manager.add(llvm::createInstructionCombiningPass());
  func_pass_manager.add(llvm::createDeadStoreEliminationPass());
  func_pass_manager.add(llvm::createDeadCodeEliminationPass());

  func_pass_manager.doInitialization();
  for (const auto &block : cfg_module->blocks()) {
    auto func = LiftBlock(&block);
    CHECK(!func->isDeclaration())
        << "Lifted block function " << func->getName().str()
        << " should have an implementation.";

    if (asm_source_writer) {
      asm_source_writer->Flush();
    }
    func_pass_manager.run(*func);
  }
  func_pass_manager.doFinalization();
}

namespace {

// Returns `true` if a basic block function looks empty, i.e. it tail-calls to
// the `__remill_detach` intrinsics. This means that a previous call to
// `remill-lift` didn't have the implementation of this block available, so
// defaulted it to detaching instead.
static bool IsBlockEmpty(const llvm::Function *func,
                         const llvm::Function *detach_func) {
  const auto &entry_block = func->front();
  if (auto term = entry_block.getTerminatingMustTailCall()) {
    return term->getCalledFunction() == detach_func &&
           entry_block.size() == 2;
  } else {
    return false;
  }
}

// Delete a basic block.
static void DeleteBlock(llvm::BasicBlock *block) {
  while (block->size()) {
    block->getInstList().pop_back();
  }
  block->eraseFromParent();
}

}  // namespace

// Lift code contained within a single block.
llvm::Function *Translator::LiftBlock(const cfg::Block *cfg_block) {
  auto block_func = GetOrCreateBlock(cfg_block->address());
  if (!block_func->isDeclaration()) {
    if (IsBlockEmpty(block_func, intrinsics->detach)) {
      DeleteBlock(&block_func->front());
      CHECK(block_func->isDeclaration())
          << "Unable to delete blocks from previously detaching block function"
          << block_func->getName().str() << ".";

    } else {
      DLOG(WARNING)
          << "Not going to lift duplicate block at "
          << std::hex << cfg_block->address() << ".";
      return block_func;
    }
  }

  AddBlockInitializationCode(block_func, basic_block);

  if (asm_source_writer) {
    asm_source_writer->WriteBlock(block_func);
  }

  // Create a block for each instruction.
  auto last_block = &block_func->back();
  auto instr_addr = cfg_block->address();
  Instruction *instr = nullptr;
  for (const auto &cfg_instr : cfg_block->instructions()) {
    CHECK(cfg_instr.address() == instr_addr)
        << "CFG Instr address " << std::hex << cfg_instr.address()
        << " doesn't match implied instruction address ("
        << std::hex << instr_addr << ") based on CFG Block structure.";

    auto instr_bytes = cfg_instr.bytes();

    // Check and delete the last instruction lifted.
    if (instr) {
      CHECK(Instruction::kCategoryNoOp == instr->category ||
            Instruction::kCategoryNormal == instr->category)
          << "Predecessor of instruction at " << std::hex << instr_addr
          << " must be a normal or no-op instruction, and not one that"
          << " should end a block.";

      // Add debug info to all previously added instructions.
      if (asm_source_writer) {
        asm_source_writer->WriteInstruction(block_func, instr);
      }

      delete instr;
      instr = nullptr;
    }

    instr = arch->DecodeInstruction(instr_addr, instr_bytes);
    CHECK(Instruction::kCategoryInvalid != instr->category)
        << "Cannot decode instruction at " << std::hex << instr_addr << ".";

    DLOG(INFO)
        << "Lifting instruction '" << instr->Serialize();

    if (auto curr_block = LiftInstruction(block_func, instr)) {
      llvm::IRBuilder<> ir(last_block);
      ir.CreateBr(curr_block);
      last_block = curr_block;
      instr_addr += instr_bytes.size();

    // Unable to lift the instruction; likely because the instruction
    // semantics are not implemented.
    //
    // TODO(pag): Add an intrinsic for this particular case.
    } else {
      AddTerminatingTailCall(last_block, intrinsics->error);
      break;
    }
  }

  CHECK(nullptr != instr)
      << "Logic error: must lift at least one instruction.";

  if (!last_block->getTerminator()) {
    LiftTerminator(last_block, instr);
  }

  if (asm_source_writer) {
    asm_source_writer->WriteInstruction(block_func, instr);
  }

  delete instr;
  return block_func;
}

namespace {

// Lift both targets of a conditional branch into a branch in the bitcode,
// where each side of the branch tail-calls to the functions associated with
// the lifted blocks for those branch targets.
static void LiftConditionalBranch(llvm::BasicBlock *source,
                                  llvm::Function *dest_true,
                                  llvm::Function *dest_false) {
  auto &context = source->getContext();
  auto function = source->getParent();
  auto block_true = llvm::BasicBlock::Create(context, "", function);
  auto block_false = llvm::BasicBlock::Create(context, "", function);

  // TODO(pag): This is a bit ugly. The idea here is that, from the semantics
  //            code, we need a way to communicate what direction of the
  //            conditional branch should be followed. It turns out to be
  //            easiest just to write to a special variable :-)
  auto branch_taken = FindVarInFunction(function, "BRANCH_TAKEN");

  llvm::IRBuilder<> cond_ir(source);
  auto cond_addr = cond_ir.CreateLoad(branch_taken);
  auto cond = cond_ir.CreateLoad(cond_addr);
  cond_ir.CreateCondBr(
      cond_ir.CreateICmpEQ(
          cond,
          llvm::ConstantInt::get(cond->getType(), 1)),
          block_true,
          block_false);

  AddTerminatingTailCall(block_true, dest_true);
  AddTerminatingTailCall(block_false, dest_false);
}

}  // namespace

// Lift the last instruction of a block as a block terminator.
void Translator::LiftTerminator(llvm::BasicBlock *block,
                                const Instruction *arch_instr) {
  switch (arch_instr->category) {
    case Instruction::kCategoryInvalid:
      LOG(FATAL)
          << "Invalid instruction category.";
      break;

    case Instruction::kCategoryNormal:
    case Instruction::kCategoryNoOp:
      AddTerminatingTailCall(
          block,
          GetOrCreateTargetBlock(arch_instr->next_pc));
      break;

    case Instruction::kCategoryError:
      AddTerminatingTailCall(block, intrinsics->error);
      break;

    case Instruction::kCategoryDirectJump:
      AddTerminatingTailCall(
          block,
          GetOrCreateTargetBlock(arch_instr->branch_taken_pc));
      break;

    case Instruction::kCategoryIndirectJump:
      AddTerminatingTailCall(block, intrinsics->jump);
      break;

    case Instruction::kCategoryDirectFunctionCall:
      AddTerminatingTailCall(
          block,
          GetOrCreateTargetBlock(arch_instr->branch_taken_pc));
      break;

    case Instruction::kCategoryIndirectFunctionCall:
      AddTerminatingTailCall(block, intrinsics->function_call);
      break;

    case Instruction::kCategoryFunctionReturn:
      AddTerminatingTailCall(block, intrinsics->function_return);
      break;

    case Instruction::kCategoryConditionalBranch:
      LiftConditionalBranch(
          block,
          GetOrCreateTargetBlock(arch_instr->branch_taken_pc),
          GetOrCreateTargetBlock(arch_instr->branch_not_taken_pc));
      break;

    case Instruction::kCategoryAsyncHyperCall:
      AddTerminatingTailCall(block, intrinsics->async_hyper_call);
      break;

    case Instruction::kCategoryConditionalAsyncHyperCall:
      LiftConditionalBranch(
          block,
          intrinsics->async_hyper_call,
          GetOrCreateTargetBlock(arch_instr->next_pc));
      break;
  }
}

namespace {

// Try to find the function that implements this semantics.
llvm::Function *GetInstructionFunction(llvm::Module *module,
                                       const std::string &function) {
  auto isel_func = FindFunction(module, function);
  if (!isel_func) {
    if (auto instr_func_alt = FindGlobaVariable(module, function)) {

      CHECK(instr_func_alt->isConstant() && instr_func_alt->hasInitializer())
          << "Expected a `constexpr` variable as the function pointer for "
          << "instruction semantic function " << function << ".";

      isel_func = llvm::dyn_cast_or_null<llvm::Function>(
          instr_func_alt->getInitializer()->stripPointerCasts());
    }
  }
  return isel_func;
}

// Create a PC operand to pass to the code implementing an unsupported
// instruction.
static Operand CreateUnsupportedInstrPC(unsigned addr_size) {
  Operand op = {};
  op.type = Operand::kTypeRegister;
  op.reg.name = "PC";
  op.reg.size = addr_size;
  op.size = addr_size;
  return op;
}

}  // namespace

// Lift a single instruction into a basic block.
llvm::BasicBlock *Translator::LiftInstruction(llvm::Function *block_func,
                                              Instruction *arch_instr) {
  auto isel_func = GetInstructionFunction(module, arch_instr->function);
  if (!isel_func) {
    LOG(ERROR)
        << "Cannot lift instruction at " << std::hex << arch_instr->pc << ", "
        << arch_instr->function << " doesn't exist.";

    isel_func = GetInstructionFunction(module, "UNSUPPORTED_INSTRUCTION");
    if (!isel_func) {
      LOG(ERROR)
          << "UNSUPPORTED_INSTRUCTION doesn't exist; not using it in place of "
          << arch_instr->function;
      return nullptr;
    }

    // This is kind of a hack, but it lets us better support unsupported
    // instructions. The idea is that we want to make sure we pass the
    // current program counter to the instruction so that we can tell the
    // hypercall, via the `State` structure, where to find the unsupported
    // instruction in memory.
    arch_instr->operands.clear();
    arch_instr->operand_size = arch->address_size;
    arch_instr->operands.push_back(
        CreateUnsupportedInstrPC(arch->address_size));
  }

  auto &context = block_func->getContext();
  auto block = llvm::BasicBlock::Create(context, "", block_func);

  llvm::IRBuilder<> ir(block);
  auto mem_ptr = FindVarInFunction(block->getParent(), "MEMORY");
  auto state_ptr = ir.CreateLoad(
      FindVarInFunction(block->getParent(), "STATE"));
  auto pc_ptr = ir.CreateLoad(FindVarInFunction(block, "PC"));
  auto next_pc_ptr = ir.CreateLoad(FindVarInFunction(block, "NEXT_PC"));

  // Update the next program counter.
  ir.CreateStore(
      ir.CreateAdd(
          ir.CreateLoad(pc_ptr),
          llvm::ConstantInt::get(
              word_type, arch_instr->next_pc - arch_instr->pc)),
      next_pc_ptr);

  // Begin an atomic block.
  if (arch_instr->is_atomic_read_modify_write) {
    ir.CreateStore(
        ir.CreateCall(intrinsics->atomic_begin, {ir.CreateLoad(mem_ptr)}),
        mem_ptr);
  }

  std::vector<llvm::Value *> args;
  args.reserve(arch_instr->operands.size() + 2);

  // First two arguments to an instruction semantics function are the
  // state pointer, and a pointer to the memory pointer.
  args.push_back(mem_ptr);
  args.push_back(state_ptr);

  auto isel_func_type = isel_func->getFunctionType();
  auto arg_num = 2U;

  for (auto &op : arch_instr->operands) {
    CHECK(arg_num < isel_func_type->getNumParams())
        << "Function " << arch_instr->function << " should have at least "
        << arg_num << " arguments.";

    auto arg_type = isel_func_type->getParamType(arg_num++);
    auto operand = LiftOperand(block, arg_type, op);
    auto op_type = operand->getType();
    CHECK(op_type == arg_type)
        << "Lifted operand " << op.Debug() << " to "
        << arch_instr->function << " does not have the correct type. Expected "
        << LLVMThingToString(arg_type) << " but got "
        << LLVMThingToString(op_type) << ".";

    args.push_back(operand);
  }

  // Call the function that implements the instruction semantics.
  ir.CreateCall(isel_func, args);

  // End an atomic block.
  if (arch_instr->is_atomic_read_modify_write) {
    ir.CreateStore(
        ir.CreateCall(intrinsics->atomic_end, {ir.CreateLoad(mem_ptr)}),
        mem_ptr);
  }

  // Update the current program counter.
  ir.CreateStore(ir.CreateLoad(next_pc_ptr), pc_ptr);

  return block;
}

namespace {

// Load the address of a register.
static llvm::Value *LoadRegAddress(llvm::BasicBlock *block,
                                   std::string reg_name) {
  return new llvm::LoadInst(
      FindVarInFunction(block->getParent(), reg_name), "", block);
}

// Load the value of a register.
static llvm::Value *LoadRegValue(llvm::BasicBlock *block,
                                 std::string reg_name) {
  return new llvm::LoadInst(LoadRegAddress(block, reg_name), "", block);
}

// Return a register value, or zero.
static llvm::Value *LoadWordRegValOrZero(llvm::BasicBlock *block,
                                         const std::string &reg_name,
                                         llvm::ConstantInt *zero) {
  if (reg_name.empty()) {
    return zero;
  }

  auto val = LoadRegValue(block, reg_name);
  auto val_type = llvm::dyn_cast_or_null<llvm::IntegerType>(val->getType());
  auto word_type = zero->getType();

  CHECK(val_type)
      << "Register " << reg_name << " expected to be an integer.";

  auto val_size = val_type->getBitWidth();
  auto word_size = word_type->getBitWidth();
  CHECK(val_size <= word_size)
      << "Register " << reg_name << " expected to be no larger than the "
      << "machine word size (" << word_type->getBitWidth() << " bits).";

  if (val_size < word_size) {
    val = new llvm::ZExtInst(val, word_type, "", block);
  }

  return val;
}

}  // namespace

// Load a register operand. This deals uniformly with write- and read-operands
// for registers. In the case of write operands, the argument type is always
// a pointer. In the case of read operands, the argument type is sometimes
// a pointer (e.g. when passing a vector to an instruction semantics function).
llvm::Value *Translator::LiftRegisterOperand(
    llvm::BasicBlock *block,
    llvm::Type *arg_type,
    const Operand::Register &arch_reg) {

  if (auto ptr_type = llvm::dyn_cast_or_null<llvm::PointerType>(arg_type)) {
    auto val = LoadRegAddress(block, arch_reg.name);
    auto val_ptr_type = llvm::dyn_cast<llvm::PointerType>(val->getType());

    // Vectors are passed as void pointers because on something like x86,
    // we want to treat XMM, YMM, and ZMM registers uniformly.
    if (val_ptr_type->getElementType() != ptr_type->getElementType()) {
      val = new llvm::BitCastInst(val, ptr_type, "", block);
    }
    return val;

  } else {
    CHECK(arg_type->isIntegerTy() || arg_type->isFloatingPointTy())
        << "Expected " << arch_reg.name << " to be an integral or float type.";

    auto val = LoadRegValue(block, arch_reg.name);

    const llvm::DataLayout data_layout(module);
    auto val_type = val->getType();
    auto val_size = data_layout.getTypeAllocSizeInBits(val_type);
    auto arg_size = data_layout.getTypeAllocSizeInBits(arg_type);
    auto word_size = data_layout.getTypeAllocSizeInBits(word_type);

    if (val_size < arg_size) {
      if (arg_type->isIntegerTy()) {
        CHECK(val_type->isIntegerTy())
            << "Expected " << arch_reg.name << " to be an integral type.";

        CHECK(word_size == arg_size)
            << "Expected integer argument to be machine word size ("
            << word_size << " bits) but is is " << arg_size << " instead.";

        val = new llvm::ZExtInst(val, word_type, "", block);

      } else if (arg_type->isFloatingPointTy()) {
        CHECK(val_type->isFloatingPointTy())
            << "Expected " << arch_reg.name << " to be a floating point type.";

        val = new llvm::FPExtInst(val, arg_type, "", block);
      }

    } else if (val_size > arg_size) {
      if (arg_type->isIntegerTy()) {
        CHECK(val_type->isIntegerTy())
            << "Expected " << arch_reg.name << " to be an integral type.";

        CHECK(word_size == arg_size)
            << "Expected integer argument to be machine word size ("
            << word_size << " bits) but is is " << arg_size << " instead.";

        val = new llvm::TruncInst(val, arg_type, "", block);

      } else if (arg_type->isFloatingPointTy()) {
        CHECK(val_type->isFloatingPointTy())
            << "Expected " << arch_reg.name << " to be a floating point type.";

        val = new llvm::FPTruncInst(val, arg_type, "", block);
      }
    }

    return val;
  }
}

// Lift an immediate operand.
llvm::Value *Translator::LiftImmediateOperand(llvm::Type *arg_type,
                                              const Operand &arch_op) {

  if (arch_op.size > word_type->getBitWidth()) {
    CHECK(arg_type->isIntegerTy(static_cast<uint32_t>(arch_op.size)))
        << "Argument to semantics function is not an integer. This may "
        << "not be surprising because the immediate operand is " <<
        arch_op.size << " bits, but the machine word size is "
        << word_type->getBitWidth() << " bits.";

    CHECK(arch_op.size <= 64)
        << "Decode error! Immediate operands can be at most 64 bits! "
        << "Operand structure encodes a truncated " << arch_op.size << " bit "
        << "value.";

    return llvm::ConstantInt::get(
        arg_type, arch_op.imm.val, arch_op.imm.is_signed);

  } else {
    CHECK(arg_type->isIntegerTy(word_type->getBitWidth()))
        << "Bad semantics function implementation. Integer constants that are "
        << "smaller than the machine word size should be represented as "
        << "machine word sized arguments to semantics functions.";

    return llvm::ConstantInt::get(
        word_type, arch_op.imm.val, arch_op.imm.is_signed);
  }
}

// Zero-extend a value to be the machine word size.
llvm::Value *Translator::LiftAddressOperand(
    llvm::BasicBlock *block, const Operand::Address &arch_addr) {

  auto zero = llvm::ConstantInt::get(word_type, 0, false);
  auto word_size = word_type->getBitWidth();

  CHECK(word_size >= arch_addr.base_reg.size)
      << "Memory base register " << arch_addr.base_reg.name
      << " is wider than the machine word size.";

  CHECK(word_size >= arch_addr.index_reg.size)
      << "Memory index register " << arch_addr.base_reg.name
      << " is wider than the machine word size.";

  auto addr = LoadWordRegValOrZero(block, arch_addr.base_reg.name, zero);
  auto index = LoadWordRegValOrZero(block, arch_addr.index_reg.name, zero);
  auto scale = llvm::ConstantInt::get(
      word_type, static_cast<uint64_t>(arch_addr.scale), true);
  auto segment = LoadWordRegValOrZero(
      block, arch_addr.segment_base_reg.name, zero);

  llvm::IRBuilder<> ir(block);
  addr = ir.CreateAdd(addr, ir.CreateMul(index, scale));

  if (0 > arch_addr.displacement) {
    addr = ir.CreateAdd(addr, llvm::ConstantInt::get(
        word_type, static_cast<uint64_t>(arch_addr.displacement)));
  } else {
    addr = ir.CreateSub(addr, llvm::ConstantInt::get(
        word_type, static_cast<uint64_t>(-arch_addr.displacement)));
  }

  // Compute the segmented address.
  if (zero != segment) {
    addr = ir.CreateAdd(addr, segment);
  }

  // Memory address is smaller than the machine word size (e.g. 32-bit address
  // used in 64-bit).
  if (arch_addr.address_size < word_size) {
    auto addr_type = llvm::Type::getIntNTy(
        block->getContext(), static_cast<unsigned>(arch_addr.address_size));

    addr = ir.CreateZExt(
        ir.CreateTrunc(addr, addr_type),
        word_type);
  }

  return addr;
}

// Lift an operand for use by the instruction.
llvm::Value *Translator::LiftOperand(llvm::BasicBlock *block,
                                     llvm::Type *arg_type,
                                     const Operand &arch_op) {
  switch (arch_op.type) {
    case Operand::kTypeInvalid:
      LOG(FATAL)
          << "Decode error! Cannot lift invalid operand.";
      return nullptr;

    case Operand::kTypeRegister:
      CHECK(arch_op.size == arch_op.reg.size)
          << "Operand size and register size must match for register "
          << arch_op.reg.name << ".";

      return LiftRegisterOperand(block, arg_type, arch_op.reg);

    case Operand::kTypeImmediate:
      return LiftImmediateOperand(arg_type, arch_op);

    case Operand::kTypeAddress:
      CHECK(arg_type == word_type)
          << "Expected that a memory operand should be represented by machine "
          << "word type.";

      return LiftAddressOperand(block, arch_op.addr);
  }

  LOG(FATAL)
      << "Got a Operand type of " << static_cast<int>(arch_op.type) << ".";

  return nullptr;
}

}  // namespace remill
