/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <functional>
#include <ios>
#include <set>
#include <string>
#include <sstream>
#include <unordered_map>
#include <utility>
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
#include "remill/BC/IntrinsicTable.h"
#include "remill/BC/Lifter.h"
#include "remill/BC/Util.h"
#include "remill/CFG/CFG.h"
#include "remill/OS/OS.h"

namespace llvm {
class ReturnInst;
}  // namespace llvm

namespace remill {
namespace {

// Initialize some attributes that are common to all newly created block
// functions. Also, give pretty names to the arguments of block functions.
static void InitBlockFunctionAttributes(llvm::Function *block_func) {

  block_func->setLinkage(llvm::GlobalValue::ExternalLinkage);
  block_func->setVisibility(llvm::GlobalValue::DefaultVisibility);

  remill::NthArgument(block_func, kMemoryPointerArgNum)->setName("memory");
  remill::NthArgument(block_func, kStatePointerArgNum)->setName("state");
  remill::NthArgument(block_func, kPCArgNum)->setName("pc");
}

// These variables must always be defined within `__remill_basic_block`.
static bool BlockHasSpecialVars(llvm::Function *basic_block) {
  return FindVarInFunction(basic_block, "STATE", true) &&
         FindVarInFunction(basic_block, "MEMORY", true) &&
         FindVarInFunction(basic_block, "PC", true) &&
         FindVarInFunction(basic_block, "BRANCH_TAKEN", true);
}

// Clang isn't guaranteed to play nice and name the LLVM values within the
// `__remill_basic_block` intrinsic with the same names as we find in the
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

Lifter::Lifter(const Arch *arch_, llvm::Module *module_)
    : arch(arch_),
      module(module_),
      blocks(),
      indirect_blocks(),
      exported_blocks(),
      basic_block(FindFunction(module, "__remill_basic_block")),
      word_type(llvm::Type::getIntNTy(
          module->getContext(), arch->address_size)),
      intrinsics(new IntrinsicTable(module)) {

  CHECK(nullptr != basic_block)
      << "Unable to find __remill_basic_block.";

  CHECK(1 == basic_block->size())
      << "Basic block template function " << basic_block->getName().str()
      << " should only have one basic block.";

  EnableDeferredInlining();
  InitFunctionAttributes(basic_block);
  InitBlockFunctionAttributes(basic_block);
  FixupBasicBlockVariables(basic_block);

  basic_block->addFnAttr(llvm::Attribute::OptimizeNone);
  basic_block->removeFnAttr(llvm::Attribute::AlwaysInline);
  basic_block->removeFnAttr(llvm::Attribute::InlineHint);
  basic_block->addFnAttr(llvm::Attribute::NoInline);
  basic_block->setVisibility(llvm::GlobalValue::DefaultVisibility);
}

Lifter::~Lifter(void) {
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

// Clone the block method template `TF` into a specific method `BF` that
// will contain lifted code.
static void AddBlockInitializationCode(llvm::Function *block_func,
                                       llvm::Function *template_func) {
  CloneFunctionInto(template_func, block_func);

  // Remove the `return` in `__remill_basic_block`.
  auto &entry = block_func->front();
  auto term = entry.getTerminator();
  term->eraseFromParent();

  block_func->removeFnAttr(llvm::Attribute::OptimizeNone);
}

}  // namespace

// Enable deferred inlining. The goal is to support better dead-store
// elimination for flags.
void Lifter::EnableDeferredInlining(void) {
  DisableInlining(intrinsics->defer_inlining);

  for (auto callers : intrinsics->defer_inlining->users()) {
    if (auto call_instr = llvm::dyn_cast_or_null<llvm::CallInst>(callers)) {
      auto bb = call_instr->getParent();
      auto caller = bb->getParent();
      DisableInlining(caller);
    }
  }
}

// Recreate a global table of named blocks.
void Lifter::SetNamedBlocks(
    std::unordered_map<std::string, llvm::Function *> &table,
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

// Recreate the global table of indirectly addressible blocks.
void Lifter::SetIndirectBlocks(void) {
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
void Lifter::CreateNamedBlocks(const cfg::Module *cfg) {
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
  }
}

// Create a function for a single block.
llvm::Function *Lifter::GetOrCreateBlock(uint64_t addr) {
  auto &block_func = blocks[addr];
  if (!block_func) {
    std::stringstream ss;
    ss << "__remill_sub_" << std::hex << addr;
    auto func_name = ss.str();

    auto func_type = basic_block->getFunctionType();
    block_func = llvm::dyn_cast<llvm::Function>(
        module->getOrInsertFunction(func_name, func_type));

    InitFunctionAttributes(block_func);

    DLOG(INFO)
        << "Created function " << func_name
        << " for block at " << std::hex << addr << ".";
  }
  return block_func;
}

// Create functions for every block in the CFG. We do this before lifting so
// that we can easily reference those blocks.
void Lifter::CreateBlocks(const cfg::Module *cfg_module) {
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
  }

  for (const auto cfg_ref_block_addr : cfg_module->referenced_blocks()) {
    auto block_func = GetOrCreateBlock(cfg_ref_block_addr);
    if (block_func->isDeclaration()) {
      block_func->setLinkage(llvm::GlobalValue::ExternalLinkage);
    }
  }

  for (const uint64_t cfg_addr_block_addr : cfg_module->addressed_blocks()) {
    auto block_func = GetOrCreateBlock(cfg_addr_block_addr);
    auto &indirect_block_func = indirect_blocks[cfg_addr_block_addr];

    CHECK(block_func == indirect_block_func || !indirect_block_func)
        << "Multiply defined addressable cfg_block at "
        << std::hex << cfg_addr_block_addr << ".";

    indirect_block_func = block_func;
  }
}

// Lift the control-flow graph specified by `cfg` into this bitcode module.
void Lifter::LiftCFG(const cfg::Module *cfg_module) {
  ForEachIndirectBlock(module,
      [this] (uintptr_t pc, llvm::Function *func) {
        blocks[pc] = func;
        indirect_blocks[pc] = func;
      });

  ForEachExportedBlock(module,
      [this] (const std::string &name, llvm::Function *lifted_func,
          llvm::Function *native_func) {
        exported_blocks[name] = lifted_func;
      });

  ForEachImportedBlock(module,
      [this] (const std::string &name, llvm::Function *lifted_func,
          llvm::Function *native_func) {
        imported_blocks[name] = lifted_func;
      });

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

  blocks.clear();
  indirect_blocks.clear();
  exported_blocks.clear();
  imported_blocks.clear();
}

// Lift code contained in blocks into the block methods.
void Lifter::LiftBlocks(const cfg::Module *cfg_module) {
  llvm::legacy::FunctionPassManager func_pass_manager(module);
  func_pass_manager.add(llvm::createCFGSimplificationPass());
  func_pass_manager.add(llvm::createPromoteMemoryToRegisterPass());
  func_pass_manager.add(llvm::createReassociatePass());
  func_pass_manager.add(llvm::createInstructionCombiningPass());
  func_pass_manager.add(llvm::createDeadStoreEliminationPass());
  func_pass_manager.add(llvm::createDeadCodeEliminationPass());

  func_pass_manager.doInitialization();
  for (const auto &cfg_block : cfg_module->blocks()) {
    auto func = LiftBlock(&cfg_block);
    CHECK(!func->isDeclaration())
        << "Lifted block function " << func->getName().str()
        << " should have an implementation.";

    func_pass_manager.run(*func);
    func->setLinkage(llvm::GlobalValue::PrivateLinkage);
  }

  func_pass_manager.doFinalization();
}

// Lift code contained within a single block.
llvm::Function *Lifter::LiftBlock(const cfg::Block *cfg_block) {
  auto block_func = GetOrCreateBlock(cfg_block->address());
  if (!block_func->isDeclaration()) {
    DLOG(WARNING)
        << "Not going to lift duplicate block at "
        << std::hex << cfg_block->address();
    return block_func;
  }

  AddBlockInitializationCode(block_func, basic_block);

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

      delete instr;
      instr = nullptr;
    }

    instr = arch->DecodeInstruction(instr_addr, instr_bytes);
    DLOG_IF(WARNING, instr_bytes.size() != instr->NumBytes())
        << "Size of decoded instruction at " << std::hex << instr_addr
        << " (" << std::dec << instr->NumBytes()
        << ") doesn't match input instruction size ("
        << instr_bytes.size() << ").";

//    DLOG(INFO)
//        << "Lifting instruction '" << instr->Serialize();

    if (auto curr_block = LiftInstruction(block_func, instr)) {
      llvm::IRBuilder<> ir(last_block);
      ir.CreateBr(curr_block);
      last_block = curr_block;
      instr_addr += instr_bytes.size();

    // Unable to lift the instruction; likely because the instruction
    // semantics are not implemented.
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
void Lifter::LiftTerminator(llvm::BasicBlock *block,
                                const Instruction *arch_instr) {
  switch (arch_instr->category) {
    case Instruction::kCategoryInvalid:
      AddTerminatingTailCall(block, intrinsics->async_hyper_call);
      break;

    case Instruction::kCategoryNormal:
    case Instruction::kCategoryNoOp:
      AddTerminatingTailCall(
          block,
          GetOrCreateBlock(arch_instr->next_pc));
      break;

    case Instruction::kCategoryError:
      AddTerminatingTailCall(block, intrinsics->error);
      break;

    case Instruction::kCategoryDirectJump:
      AddTerminatingTailCall(
          block,
          GetOrCreateBlock(arch_instr->branch_taken_pc));
      break;

    case Instruction::kCategoryIndirectJump:
      AddTerminatingTailCall(block, intrinsics->jump);
      break;

    case Instruction::kCategoryDirectFunctionCall:
      AddTerminatingTailCall(
          block,
          GetOrCreateBlock(arch_instr->branch_taken_pc));
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
          GetOrCreateBlock(arch_instr->branch_taken_pc),
          GetOrCreateBlock(arch_instr->branch_not_taken_pc));
      break;

    case Instruction::kCategoryAsyncHyperCall:
      AddTerminatingTailCall(block, intrinsics->async_hyper_call);
      break;

    case Instruction::kCategoryConditionalAsyncHyperCall:
      LiftConditionalBranch(
          block,
          intrinsics->async_hyper_call,
          GetOrCreateBlock(arch_instr->next_pc));
      break;
  }
}

namespace {

// Try to find the function that implements this semantics.
llvm::Function *GetInstructionFunction(llvm::Module *module,
                                       const std::string &function) {
  auto isel = FindGlobaVariable(module, function);
  if (!isel) {
    return nullptr;  // Falls back on `UNIMPLEMENTED_INSTRUCTION`.
  }

  if (!isel->isConstant() || !isel->hasInitializer()) {
    LOG(FATAL)
        << "Expected a `constexpr` variable as the function pointer for "
        << "instruction semantic function " << function
        << ": " << LLVMThingToString(isel);
  }

  auto sem = isel->getInitializer()->stripPointerCasts();
  return llvm::dyn_cast_or_null<llvm::Function>(sem);
}

}  // namespace

// Lift a single instruction into a basic block.
llvm::BasicBlock *Lifter::LiftInstruction(llvm::Function *block_func,
                                              Instruction *arch_instr) {
  auto isel_func = GetInstructionFunction(module, arch_instr->function);

  if(arch_instr->category == Instruction::kCategoryInvalid) {
    isel_func = GetInstructionFunction(module, "INVALID_INSTRUCTION");
  }

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

    arch_instr->operands.clear();
  }

  auto &context = block_func->getContext();
  auto block = llvm::BasicBlock::Create(context, "", block_func);

  llvm::IRBuilder<> ir(block);
  auto mem_ptr = LoadMemoryPointerRef(block);
  auto state_ptr = LoadStatePointer(block);
  auto pc_ptr = LoadProgramCounterRef(block);

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
        << "Function " << arch_instr->function << ", implemented by "
        << isel_func->getName().str() << ", should have at least "
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

  // Update the current program counter. Control-flow instructions may update
  // the program counter in the semantics code.
  ir.CreateStore(
      ir.CreateAdd(
          ir.CreateLoad(pc_ptr),
          llvm::ConstantInt::get(word_type, arch_instr->NumBytes())),
      pc_ptr);

  // Call the function that implements the instruction semantics.
  ir.CreateCall(isel_func, args);

  // End an atomic block.
  if (arch_instr->is_atomic_read_modify_write) {
    ir.CreateStore(
        ir.CreateCall(intrinsics->atomic_end, {ir.CreateLoad(mem_ptr)}),
        mem_ptr);
  }

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
llvm::Value *Lifter::LiftRegisterOperand(
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
llvm::Value *Lifter::LiftImmediateOperand(llvm::Type *arg_type,
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
llvm::Value *Lifter::LiftAddressOperand(
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

  if (zero != index) {
    addr = ir.CreateAdd(addr, ir.CreateMul(index, scale));
  }

  if (arch_addr.displacement) {
    if (0 < arch_addr.displacement) {
      addr = ir.CreateAdd(addr, llvm::ConstantInt::get(
          word_type, static_cast<uint64_t>(arch_addr.displacement)));
    } else {
      addr = ir.CreateSub(addr, llvm::ConstantInt::get(
          word_type, static_cast<uint64_t>(-arch_addr.displacement)));
    }
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
llvm::Value *Lifter::LiftOperand(llvm::BasicBlock *block,
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
      if (arg_type != word_type) {
        LOG(FATAL)
            << "Expected that a memory operand should be represented by "
            << "machine word type. Argument type is "
            << LLVMThingToString(arg_type) << " and word type is "
            << LLVMThingToString(word_type);
      }

      return LiftAddressOperand(block, arch_op.addr);
  }

  LOG(FATAL)
      << "Got a Operand type of " << static_cast<int>(arch_op.type) << ".";

  return nullptr;
}

}  // namespace remill
