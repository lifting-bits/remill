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
#include "remill/CFG/BlockHasher.h"
#include "remill/CFG/CFG.h"
#include "remill/OS/OS.h"

DEFINE_bool(add_breakpoints, false,
            "Add calls to the `BREAKPOINT_INSTRUCTION` before every lifted "
            "instruction. The semantics for this instruction call into a "
            "breakpoint hyper call.");

namespace remill {


Lifter::Lifter(const Arch *arch_, llvm::Module *module_)
    : arch(arch_),
      module(module_),
      pc_to_block(),
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

namespace {

static uint64_t GetBlockId(const cfg::Block &cfg_block) {
  if (cfg_block.has_id()) {
    return cfg_block.id();
  } else {
    return BlockHasher().HashBlock(cfg_block);
  }
}

}  // namespace

// Create a function for a single decoded block.
void Lifter::CreateBlock(const cfg::Block &cfg_block) {
  auto id = GetBlockId(cfg_block);
  auto pc = cfg_block.address();

  auto id_it = id_to_block.find(id);
  if (id_it != id_to_block.end()) {
    pc_to_block[pc] = id_it->second;
  }

  auto &block_func = pc_to_block[pc];
  if (!block_func) {
    std::stringstream ss;
    ss << "__remill_sub_" << std::hex << id;
    auto func_name = ss.str();
    auto func_type = basic_block->getFunctionType();

    block_func = llvm::Function::Create(
        func_type, llvm::GlobalValue::PrivateLinkage, ".", module);

    auto block_var = new llvm::GlobalVariable(
        *module, llvm::PointerType::get(func_type, 0), true,
        llvm::GlobalValue::ExternalLinkage, block_func, func_name);

    CHECK(block_var->getName() == func_name)
        << "Duplicate block for " << func_name;

    InitFunctionAttributes(block_func);
    SetBlockPC(block_var, pc);
    SetBlockId(block_var, id);

    id_to_block[id] = block_func;

    if (cfg_block.has_name()) {
      DLOG(INFO)
          << "Block at " << std::hex << pc << " has name " << cfg_block.name();
      SetBlockName(block_func, cfg_block.name());
    }

  } else {
    uint64_t other_id = 0;
    if (!TryGetBlockId(block_func, other_id) || other_id != id) {
      DLOG(FATAL)
          << "Duplicate cfg_block at PC " << std::hex << pc << " exists in "
          << "the CFG proto. There should only be one version of each block "
          << "in a given CFG Module.";
    } else {
      DLOG(ERROR)
          << "Duplicate cfg_block at PC " << std::hex << pc << " exists in "
          << "the CFG Module, but they both have the same ID.";
    }
  }
}

// Create a function for a single block.
llvm::Function *Lifter::GetBlock(uint64_t addr) {
  auto &block_func = pc_to_block[addr];
  if (!block_func) {
    LOG(WARNING)
        << "Unable find block for PC " << std::hex << addr
        << " reverting to `__remill_missing_block`.";
    block_func = intrinsics->missing_block;
  }
  return block_func;
}

// Lift the control-flow graph specified by `cfg` into this bitcode module.
void Lifter::LiftCFG(const cfg::Module *cfg_module) {
  ForEachBlock(module,
      [this] (uint64_t pc, uint64_t id, llvm::Function *func) {
    id_to_block[id] = func;
  });

  for (auto &cfg_block : cfg_module->blocks()) {
    CreateBlock(cfg_block);
  }

  LiftBlocks(cfg_module);

  pc_to_block.clear();
  id_to_block.clear();
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
    auto func = LiftBlock(cfg_block);
    CHECK(!func->isDeclaration())
        << "Lifted block function " << func->getName().str()
        << " should have an implementation.";

    func_pass_manager.run(*func);
  }

  func_pass_manager.doFinalization();
}

// Lift code contained within a single block.
llvm::Function *Lifter::LiftBlock(const cfg::Block &cfg_block) {
  auto block_func = GetBlock(cfg_block.address());
  if (!block_func->isDeclaration()) {
    return block_func;
  }

  CloneBlockFunctionInto(block_func);

  InstructionLifter lifter(word_type, intrinsics);

  // Create a block for each instruction.
  auto last_block = &block_func->back();
  auto instr_addr = cfg_block.address();
  Instruction *instr = nullptr;
  for (const auto &cfg_instr : cfg_block.instructions()) {
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

    if (auto curr_block = LiftInstruction(block_func, instr, lifter)) {
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

// Lift a single instruction into a basic block.
llvm::BasicBlock *Lifter::LiftInstruction(llvm::Function *block_func,
                                          Instruction *instr,
                                          InstructionLifter &lifter) {
  auto &context = block_func->getContext();
  auto block = llvm::BasicBlock::Create(context, "", block_func);
  if (!lifter.LiftIntoBlock(instr, block)) {
    block->eraseFromParent();
    return nullptr;
  }
  return block;
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
          GetBlock(arch_instr->next_pc));
      break;

    case Instruction::kCategoryError:
      AddTerminatingTailCall(block, intrinsics->error);
      break;

    case Instruction::kCategoryDirectJump:
      AddTerminatingTailCall(
          block,
          GetBlock(arch_instr->branch_taken_pc));
      break;

    case Instruction::kCategoryIndirectJump:
      AddTerminatingTailCall(block, intrinsics->jump);
      break;

    case Instruction::kCategoryDirectFunctionCall:
      AddTerminatingTailCall(
          block,
          GetBlock(arch_instr->branch_taken_pc));
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
          GetBlock(arch_instr->branch_taken_pc),
          GetBlock(arch_instr->branch_not_taken_pc));
      break;

    case Instruction::kCategoryAsyncHyperCall:
      AddTerminatingTailCall(block, intrinsics->async_hyper_call);
      break;

    case Instruction::kCategoryConditionalAsyncHyperCall:
      LiftConditionalBranch(
          block,
          intrinsics->async_hyper_call,
          GetBlock(arch_instr->next_pc));
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

InstructionLifter::~InstructionLifter(void) {}

InstructionLifter::InstructionLifter(llvm::IntegerType *word_type_,
                                     const IntrinsicTable *intrinsics_)
    : word_type(word_type_),
      intrinsics(intrinsics_) {}

// Lift a single instruction into a basic block.
bool InstructionLifter::LiftIntoBlock(
    Instruction *arch_instr, llvm::BasicBlock *block) {

  auto module = block->getModule();
  auto isel_func = GetInstructionFunction(module, arch_instr->function);

  if (Instruction::kCategoryInvalid == arch_instr->category) {
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
      return false;
    }

    arch_instr->operands.clear();
  }

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
  args.push_back(nullptr);
  args.push_back(state_ptr);

  // Call out to a special 'breakpoint' instruction function, that lets us
  // interpose on the machine state just before every lifted instruction.
  if (FLAGS_add_breakpoints) {
    ir.CreateStore(
        ir.CreateCall(GetInstructionFunction(module, "BREAKPOINT_INSTRUCTION"),
                      args),
        mem_ptr);
  }

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

  // Pass in current value of the memory pointer.
  args[0] = ir.CreateLoad(mem_ptr);

  // Call the function that implements the instruction semantics.
  ir.CreateStore(ir.CreateCall(isel_func, args), mem_ptr);

  // End an atomic block.
  if (arch_instr->is_atomic_read_modify_write) {
    ir.CreateStore(
        ir.CreateCall(intrinsics->atomic_end, {ir.CreateLoad(mem_ptr)}),
        mem_ptr);
  }

  return true;
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
llvm::Value *InstructionLifter::LiftRegisterOperand(
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

    const llvm::DataLayout data_layout(block->getModule());
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
llvm::Value *InstructionLifter::LiftImmediateOperand(llvm::Type *arg_type,
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
llvm::Value *InstructionLifter::LiftAddressOperand(
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
llvm::Value *InstructionLifter::LiftOperand(llvm::BasicBlock *block,
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
