/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "remill/BC/Lifter.h"

#include <glog/logging.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Operator.h>
#include <llvm/IR/Type.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/ValueMapper.h>

#include <functional>
#include <ios>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Instruction.h"
#include "remill/Arch/Name.h"
#include "remill/BC/ABI.h"
#include "remill/BC/Compat/DataLayout.h"
#include "remill/BC/IntrinsicTable.h"
#include "remill/BC/Util.h"
#include "remill/OS/OS.h"

namespace remill {
namespace {

// Try to find the function that implements this semantics.
llvm::Function *GetInstructionFunction(llvm::Module *module,
                                       const std::string &function) {
  std::stringstream ss;
  ss << "ISEL_" << function;
  auto isel_name = ss.str();

  auto isel = FindGlobaVariable(module, isel_name);
  if (!isel) {
    return nullptr;  // Falls back on `UNIMPLEMENTED_INSTRUCTION`.
  }

  if (!isel->isConstant() || !isel->hasInitializer()) {
    LOG(FATAL) << "Expected a `constexpr` variable as the function pointer for "
               << "instruction semantic function " << function << ": "
               << LLVMThingToString(isel);
  }

  auto sem = isel->getInitializer()->stripPointerCasts();
  return llvm::dyn_cast_or_null<llvm::Function>(sem);
}

}  // namespace

InstructionLifter::~InstructionLifter(void) {}

InstructionLifter::InstructionLifter(const Arch *arch_,
                                     const IntrinsicTable *intrinsics_)
    : arch(arch_),
      word_type(llvm::Type::getIntNTy(
          intrinsics_->async_hyper_call->getContext(), arch->address_size)),
      intrinsics(intrinsics_),
      last_func(nullptr) {}

// Lift a single instruction into a basic block. `is_delayed` signifies that
// this instruction will execute within the delay slot of another instruction.
LiftStatus InstructionLifter::LiftIntoBlock(Instruction &inst,
                                            llvm::BasicBlock *block,
                                            bool is_delayed) {
  return LiftIntoBlock(inst, block,
                       NthArgument(block->getParent(), kStatePointerArgNum),
                       is_delayed);
}

// Lift a single instruction into a basic block.
LiftStatus InstructionLifter::LiftIntoBlock(Instruction &arch_inst,
                                            llvm::BasicBlock *block,
                                            llvm::Value *state_ptr,
                                            bool is_delayed) {

  llvm::Function *const func = block->getParent();
  llvm::Module *const module = func->getParent();
  llvm::Function *isel_func = nullptr;
  auto status = kLiftedInstruction;

  if (func != last_func) {
    reg_ptr_cache.clear();
  }
  last_func = func;

  if (arch_inst.IsValid()) {
    isel_func = GetInstructionFunction(module, arch_inst.function);
  } else {
    LOG(ERROR) << "Cannot decode instruction bytes at " << std::hex
               << arch_inst.pc << std::dec;

    isel_func = GetInstructionFunction(module, "INVALID_INSTRUCTION");
    CHECK(isel_func != nullptr) << "INVALID_INSTRUCTION doesn't exist.";

    arch_inst.operands.clear();
    status = kLiftedInvalidInstruction;
  }

  if (!isel_func) {
    LOG(ERROR) << "Missing semantics for instruction " << arch_inst.Serialize();

    isel_func = GetInstructionFunction(module, "UNSUPPORTED_INSTRUCTION");
    CHECK(isel_func != nullptr)
        << "UNSUPPORTED_INSTRUCTION doesn't exist; not using it in place of "
        << arch_inst.function;

    arch_inst.operands.clear();
    status = kLiftedUnsupportedInstruction;
  }

  llvm::IRBuilder<> ir(block);
  const auto mem_ptr_ref = LoadRegAddress(block, state_ptr, "MEMORY");
  const auto pc_ref = LoadRegAddress(block, state_ptr, "PC");
  const auto next_pc_ref = LoadRegAddress(block, state_ptr, "NEXT_PC");
  const auto next_pc = ir.CreateLoad(next_pc_ref);

  // If this instruction appears within a delay slot, then we're going to assume
  // that the prior instruction updated `PC` to the target of the CTI, and that
  // the value in `NEXT_PC` on entry to this instruction represents the actual
  // address of this instruction, so we'll swap `PC` and `NEXT_PC`.
  //
  // TODO(pag): An alternate approach may be to call some kind of `DELAY_SLOT`
  //            semantics function.
  if (is_delayed) {
    llvm::Value *temp_args[] = {ir.CreateLoad(mem_ptr_ref)};
    ir.CreateStore(ir.CreateCall(intrinsics->delay_slot_begin, temp_args),
                   mem_ptr_ref);

    // Leave `PC` and `NEXT_PC` alone; we assume that the semantics have done
    // the right thing initializing `PC` and `NEXT_PC` for the delay slots.

  } else {

    // Update the current program counter. Control-flow instructions may update
    // the program counter in the semantics code.
    ir.CreateStore(next_pc, pc_ref);
    ir.CreateStore(
        ir.CreateAdd(next_pc,
                     llvm::ConstantInt::get(word_type, arch_inst.bytes.size())),
        next_pc_ref);
  }

  // Begin an atomic block.
  if (arch_inst.is_atomic_read_modify_write) {
    llvm::Value *temp_args[] = {ir.CreateLoad(mem_ptr_ref)};
    ir.CreateStore(ir.CreateCall(intrinsics->atomic_begin, temp_args),
                   mem_ptr_ref);
  }

  std::vector<llvm::Value *> args;
  args.reserve(arch_inst.operands.size() + 2);

  // First two arguments to an instruction semantics function are the
  // state pointer, and a pointer to the memory pointer.
  args.push_back(nullptr);
  args.push_back(state_ptr);

  auto isel_func_type = isel_func->getFunctionType();
  auto arg_num = 2U;

  for (auto &op : arch_inst.operands) {
    CHECK(arg_num < isel_func_type->getNumParams())
        << "Function " << arch_inst.function << ", implemented by "
        << isel_func->getName().str() << ", should have at least " << arg_num
        << " arguments for instruction " << arch_inst.Serialize();

    auto arg = NthArgument(isel_func, arg_num);
    auto arg_type = arg->getType();
    auto operand = LiftOperand(arch_inst, block, state_ptr, arg, op);
    arg_num += 1;
    auto op_type = operand->getType();
    CHECK(op_type == arg_type)
        << "Lifted operand " << op.Serialize() << " to " << arch_inst.function
        << " does not have the correct type. Expected "
        << LLVMThingToString(arg_type) << " but got "
        << LLVMThingToString(op_type) << ".";

    args.push_back(operand);
  }

  // Pass in current value of the memory pointer.
  args[0] = ir.CreateLoad(mem_ptr_ref);

  // Call the function that implements the instruction semantics.
  ir.CreateStore(ir.CreateCall(isel_func, args), mem_ptr_ref);

  // End an atomic block.
  if (arch_inst.is_atomic_read_modify_write) {
    llvm::Value *temp_args[] = {ir.CreateLoad(mem_ptr_ref)};
    ir.CreateStore(ir.CreateCall(intrinsics->atomic_end, temp_args),
                   mem_ptr_ref);
  }

  // Restore the true target of the delayed branch.
  if (is_delayed) {

    // This is the delayed update of the program counter.
    ir.CreateStore(next_pc, pc_ref);

    // We don't know what the `NEXT_PC` is going to be because of the next
    // instruction size is unknown (really, it's likely to be
    // `arch->MaxInstructionSize()`), and for normal instructions, before they
    // are lifted, we do the `PC = NEXT_PC + size`, so this is fine.
    ir.CreateStore(next_pc, next_pc_ref);

    llvm::Value *temp_args[] = {ir.CreateLoad(mem_ptr_ref)};
    ir.CreateStore(ir.CreateCall(intrinsics->delay_slot_end, temp_args),
                   mem_ptr_ref);
  }

  return status;
}

// Load the address of a register.
llvm::Value *InstructionLifter::LoadRegAddress(llvm::BasicBlock *block,
                                               llvm::Value *state_ptr,
                                               const std::string &reg_name) {
  const auto func = block->getParent();
  if (func != last_func) {
    reg_ptr_cache.clear();
  }

  const auto reg_ptr_it = reg_ptr_cache.find(reg_name);
  if (reg_ptr_it != reg_ptr_cache.end()) {
    return reg_ptr_it->second;

  // It's a register known to this architecture, so go and build a GEP to it
  // right now. We'll try to be careful about the placement of the actual
  // indexing instructions so that they always follow the definition of the
  // state pointer, and thus are most likely to dominate all future uses.
  } else if (auto reg = arch->RegisterByName(reg_name); reg) {

    llvm::Value *reg_ptr = nullptr;

    // The state pointer is an argument.
    if (auto state_arg = llvm::dyn_cast<llvm::Argument>(state_ptr); state_arg) {
      DCHECK_EQ(state_arg->getParent(), block->getParent());
      auto &target_block = block->getParent()->getEntryBlock();
      llvm::IRBuilder<> ir(&target_block, target_block.getFirstInsertionPt());
      reg_ptr = reg->AddressOf(state_ptr, ir);

    // The state pointer is an instruction, likely an `AllocaInst`.
    } else if (auto state_inst = llvm::dyn_cast<llvm::Instruction>(state_ptr);
               state_inst) {
      llvm::IRBuilder<> ir(state_inst);
      reg_ptr = reg->AddressOf(state_ptr, ir);

    // The state pointer is a constant, likely an `llvm::GlobalVariable`.
    } else if (auto state_const = llvm::dyn_cast<llvm::Constant>(state_ptr);
               state_const) {
      reg_ptr = reg->AddressOf(state_ptr, block);

    // Not sure.
    } else {
      LOG(FATAL) << "Unsupported value type for the State pointer: "
                 << LLVMThingToString(state_ptr);
    }

    reg_ptr_cache.emplace(reg_name, reg_ptr);
    return reg_ptr;

  } else {
    const auto reg_ptr = FindVarInFunction(func, reg_name, true);
    reg_ptr_cache.emplace(reg_name, reg_ptr);
    return reg_ptr;
  }
}

// Load the value of a register.
llvm::Value *InstructionLifter::LoadRegValue(llvm::BasicBlock *block,
                                             llvm::Value *state_ptr,
                                             const std::string &reg_name) {
  return new llvm::LoadInst(LoadRegAddress(block, state_ptr, reg_name), "",
                            block);
}

// Return a register value, or zero.
llvm::Value *InstructionLifter::LoadWordRegValOrZero(
    llvm::BasicBlock *block, llvm::Value *state_ptr,
    const std::string &reg_name, llvm::ConstantInt *zero) {

  if (reg_name.empty()) {
    return zero;
  }

  auto val = LoadRegValue(block, state_ptr, reg_name);
  auto val_type = llvm::dyn_cast_or_null<llvm::IntegerType>(val->getType());
  auto word_type = zero->getType();

  CHECK(val_type) << "Register " << reg_name << " expected to be an integer.";

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

llvm::Value *InstructionLifter::LiftShiftRegisterOperand(
    Instruction &inst, llvm::BasicBlock *block, llvm::Value *state_ptr,
    llvm::Argument *arg, Operand &op) {

  llvm::Function *func = block->getParent();
  llvm::Module *module = func->getParent();
  auto &context = module->getContext();
  auto &arch_reg = op.shift_reg.reg;

  auto arg_type = arg->getType();
  CHECK(arg_type->isIntegerTy())
      << "Expected " << arch_reg.name << " to be an integral type "
      << "for instruction at " << std::hex << inst.pc;

  const llvm::DataLayout data_layout(module);
  auto reg = LoadRegValue(block, state_ptr, arch_reg.name);
  auto reg_type = reg->getType();
  auto reg_size = SizeOfTypeInBits(data_layout, reg_type);
  auto word_size = SizeOfTypeInBits(data_layout, word_type);
  auto op_type = llvm::Type::getIntNTy(context, op.size);

  const uint64_t zero = 0;
  const uint64_t one = 1;
  const uint64_t shift_size = op.shift_reg.shift_size;

  const auto shift_val = llvm::ConstantInt::get(op_type, shift_size);

  llvm::IRBuilder<> ir(block);

  auto curr_size = reg_size;
  if (Operand::ShiftRegister::kExtendInvalid != op.shift_reg.extend_op) {

    auto extract_type =
        llvm::Type::getIntNTy(context, op.shift_reg.extract_size);

    if (reg_size > op.shift_reg.extract_size) {
      curr_size = op.shift_reg.extract_size;
      reg = ir.CreateTrunc(reg, extract_type);

    } else {
      CHECK(reg_size == op.shift_reg.extract_size)
          << "Invalid extraction size. Can't extract "
          << op.shift_reg.extract_size << " bits from a " << reg_size
          << "-bit value in operand " << op.Serialize() << " of instruction at "
          << std::hex << inst.pc;
    }

    if (op.size > op.shift_reg.extract_size) {
      switch (op.shift_reg.extend_op) {
        case Operand::ShiftRegister::kExtendSigned:
          reg = ir.CreateSExt(reg, op_type);
          curr_size = op.size;
          break;
        case Operand::ShiftRegister::kExtendUnsigned:
          reg = ir.CreateZExt(reg, op_type);
          curr_size = op.size;
          break;
        default:
          LOG(FATAL) << "Invalid extend operation type for instruction at "
                     << std::hex << inst.pc;
          break;
      }
    }
  }

  CHECK(curr_size <= op.size);

  if (curr_size < op.size) {
    reg = ir.CreateZExt(reg, op_type);
    curr_size = op.size;
  }

  if (Operand::ShiftRegister::kShiftInvalid != op.shift_reg.shift_op) {

    CHECK(shift_size < op.size)
        << "Shift of size " << shift_size
        << " is wider than the base register size in shift register in "
        << inst.Serialize();

    switch (op.shift_reg.shift_op) {

      // Left shift.
      case Operand::ShiftRegister::kShiftLeftWithZeroes:
        reg = ir.CreateShl(reg, shift_val);
        break;

      // Masking shift left.
      case Operand::ShiftRegister::kShiftLeftWithOnes: {
        const auto mask_val =
            llvm::ConstantInt::get(reg_type, ~((~zero) << shift_size));
        reg = ir.CreateOr(ir.CreateShl(reg, shift_val), mask_val);
        break;
      }

      // Logical right shift.
      case Operand::ShiftRegister::kShiftUnsignedRight:
        reg = ir.CreateLShr(reg, shift_val);
        break;

      // Arithmetic right shift.
      case Operand::ShiftRegister::kShiftSignedRight:
        reg = ir.CreateAShr(reg, shift_val);
        break;

      // Rotate left.
      case Operand::ShiftRegister::kShiftLeftAround: {
        const uint64_t shr_amount = (~shift_size + one) & (op.size - one);
        const auto shr_val = llvm::ConstantInt::get(op_type, shr_amount);
        const auto val1 = ir.CreateLShr(reg, shr_val);
        const auto val2 = ir.CreateShl(reg, shift_val);
        reg = ir.CreateOr(val1, val2);
        break;
      }

      // Rotate right.
      case Operand::ShiftRegister::kShiftRightAround: {
        const uint64_t shl_amount = (~shift_size + one) & (op.size - one);
        const auto shl_val = llvm::ConstantInt::get(op_type, shl_amount);
        const auto val1 = ir.CreateLShr(reg, shift_val);
        const auto val2 = ir.CreateShl(reg, shl_val);
        reg = ir.CreateOr(val1, val2);
        break;
      }

      case Operand::ShiftRegister::kShiftInvalid: break;
    }
  }

  if (word_size > op.size) {
    reg = ir.CreateZExt(reg, word_type);
  } else {
    CHECK(word_size == op.size)
        << "Final size of operand " << op.Serialize() << " is " << op.size
        << " bits, but address size is " << word_size;
  }

  return reg;
}

namespace {

static llvm::Type *IntendedArgumentType(llvm::Argument *arg) {
  for (auto user : arg->users()) {
    if (auto cast_inst = llvm::dyn_cast<llvm::IntToPtrInst>(user)) {
      return cast_inst->getType();
    }
  }
  return arg->getType();
}

static llvm::Value *
ConvertToIntendedType(Instruction &inst, Operand &op, llvm::BasicBlock *block,
                      llvm::Value *val, llvm::Type *intended_type) {
  auto val_type = val->getType();
  if (val->getType() == intended_type) {
    return val;
  } else if (auto val_ptr_type = llvm::dyn_cast<llvm::PointerType>(val_type)) {
    if (intended_type->isPointerTy()) {
      return new llvm::BitCastInst(val, intended_type, val->getName(), block);
    } else if (intended_type->isIntegerTy()) {
      return new llvm::PtrToIntInst(val, intended_type, val->getName(), block);
    }
  } else if (val_type->isFloatingPointTy()) {
    if (intended_type->isIntegerTy()) {
      return new llvm::BitCastInst(val, intended_type, val->getName(), block);
    }
  }

  LOG(FATAL) << "Unable to convert value " << LLVMThingToString(val)
             << " to intended argument type "
             << LLVMThingToString(intended_type) << " for operand "
             << op.Serialize() << " of instruction " << inst.Serialize();

  return nullptr;
}

}  // namespace

// Load a register operand. This deals uniformly with write- and read-operands
// for registers. In the case of write operands, the argument type is always
// a pointer. In the case of read operands, the argument type is sometimes
// a pointer (e.g. when passing a vector to an instruction semantics function).
llvm::Value *InstructionLifter::LiftRegisterOperand(Instruction &inst,
                                                    llvm::BasicBlock *block,
                                                    llvm::Value *state_ptr,
                                                    llvm::Argument *arg,
                                                    Operand &op) {

  llvm::Function *func = block->getParent();
  llvm::Module *module = func->getParent();
  auto &arch_reg = op.reg;

  const auto real_arg_type = arg->getType();

  // LLVM on AArch64 and on amd64 Windows converts things like `RnW<uint64_t>`,
  // which is a struct containing a `uint64_t *`, into a `uintptr_t` when they
  // are being passed as arguments.
  auto arg_type = IntendedArgumentType(arg);

  if (llvm::isa<llvm::PointerType>(arg_type)) {
    auto val = LoadRegAddress(block, state_ptr, arch_reg.name);
    return ConvertToIntendedType(inst, op, block, val, real_arg_type);

  } else {
    CHECK(arg_type->isIntegerTy() || arg_type->isFloatingPointTy())
        << "Expected " << arch_reg.name << " to be an integral or float type "
        << "for instruction at " << std::hex << inst.pc;

    auto val = LoadRegValue(block, state_ptr, arch_reg.name);

    const llvm::DataLayout data_layout(module);
    auto val_type = val->getType();
    auto val_size = data_layout.getTypeAllocSizeInBits(val_type);
    auto arg_size = data_layout.getTypeAllocSizeInBits(arg_type);
    auto word_size = data_layout.getTypeAllocSizeInBits(word_type);

    if (val_size < arg_size) {
      if (arg_type->isIntegerTy()) {
        CHECK(val_type->isIntegerTy())
            << "Expected " << arch_reg.name << " to be an integral type "
            << "for instruction at " << std::hex << inst.pc;

        CHECK(word_size == arg_size)
            << "Expected integer argument to be machine word size ("
            << word_size << " bits) but is is " << arg_size << " instead "
            << "in instruction at " << std::hex << inst.pc;

        val = new llvm::ZExtInst(val, word_type, "", block);

      } else if (arg_type->isFloatingPointTy()) {
        CHECK(val_type->isFloatingPointTy())
            << "Expected " << arch_reg.name << " to be a floating point type "
            << "for instruction at " << std::hex << inst.pc;

        val = new llvm::FPExtInst(val, arg_type, "", block);
      }

    } else if (val_size > arg_size) {
      if (arg_type->isIntegerTy()) {
        CHECK(val_type->isIntegerTy())
            << "Expected " << arch_reg.name << " to be an integral type "
            << "for instruction at " << std::hex << inst.pc;

        CHECK(word_size == arg_size)
            << "Expected integer argument to be machine word size ("
            << word_size << " bits) but is is " << arg_size << " instead "
            << "in instruction at " << std::hex << inst.pc;

        val = new llvm::TruncInst(val, arg_type, "", block);

      } else if (arg_type->isFloatingPointTy()) {
        CHECK(val_type->isFloatingPointTy())
            << "Expected " << arch_reg.name << " to be a floating point type "
            << "for instruction at " << std::hex << inst.pc;

        val = new llvm::FPTruncInst(val, arg_type, "", block);
      }
    }

    return ConvertToIntendedType(inst, op, block, val, real_arg_type);
  }
}

// Lift an immediate operand.
llvm::Value *
InstructionLifter::LiftImmediateOperand(Instruction &inst, llvm::BasicBlock *,
                                        llvm::Argument *arg, Operand &arch_op) {
  auto arg_type = arg->getType();
  if (arch_op.size > word_type->getBitWidth()) {
    CHECK(arg_type->isIntegerTy(static_cast<uint32_t>(arch_op.size)))
        << "Argument to semantics function for instruction at " << std::hex
        << inst.pc << " is not an integer. This may not be surprising because "
        << "the immediate operand is " << arch_op.size << " bits, but the "
        << "machine word size is " << word_type->getBitWidth() << " bits.";

    CHECK(arch_op.size <= 64)
        << "Decode error! Immediate operands can be at most 64 bits! "
        << "Operand structure encodes a truncated " << arch_op.size << " bit "
        << "value for instruction at " << std::hex << inst.pc;

    return llvm::ConstantInt::get(arg_type, arch_op.imm.val,
                                  arch_op.imm.is_signed);

  } else {
    CHECK(arg_type->isIntegerTy(word_type->getBitWidth()))
        << "Bad semantics function implementation for instruction at "
        << std::hex << inst.pc << ". Integer constants that are "
        << "smaller than the machine word size should be represented as "
        << "machine word sized arguments to semantics functions.";

    return llvm::ConstantInt::get(word_type, arch_op.imm.val,
                                  arch_op.imm.is_signed);
  }
}

// Zero-extend a value to be the machine word size.
llvm::Value *InstructionLifter::LiftAddressOperand(Instruction &inst,
                                                   llvm::BasicBlock *block,
                                                   llvm::Value *state_ptr,
                                                   llvm::Argument *,
                                                   Operand &op) {
  auto &arch_addr = op.addr;
  auto zero = llvm::ConstantInt::get(word_type, 0, false);
  auto word_size = word_type->getBitWidth();

  CHECK(word_size >= arch_addr.base_reg.size)
      << "Memory base register " << arch_addr.base_reg.name
      << "for instruction at " << std::hex << inst.pc
      << " is wider than the machine word size.";

  CHECK(word_size >= arch_addr.index_reg.size)
      << "Memory index register " << arch_addr.base_reg.name
      << "for instruction at " << std::hex << inst.pc
      << " is wider than the machine word size.";

  auto addr =
      LoadWordRegValOrZero(block, state_ptr, arch_addr.base_reg.name, zero);
  auto index =
      LoadWordRegValOrZero(block, state_ptr, arch_addr.index_reg.name, zero);
  auto scale = llvm::ConstantInt::get(
      word_type, static_cast<uint64_t>(arch_addr.scale), true);
  auto segment = LoadWordRegValOrZero(block, state_ptr,
                                      arch_addr.segment_base_reg.name, zero);

  llvm::IRBuilder<> ir(block);

  if (zero != index) {
    addr = ir.CreateAdd(addr, ir.CreateMul(index, scale));
  }

  if (arch_addr.displacement) {
    if (0 < arch_addr.displacement) {
      addr = ir.CreateAdd(
          addr, llvm::ConstantInt::get(
                    word_type, static_cast<uint64_t>(arch_addr.displacement)));
    } else {
      addr = ir.CreateSub(
          addr, llvm::ConstantInt::get(
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

    addr = ir.CreateZExt(ir.CreateTrunc(addr, addr_type), word_type);
  }

  return addr;
}

// Lift an operand for use by the instruction.
llvm::Value *
InstructionLifter::LiftOperand(Instruction &inst, llvm::BasicBlock *block,
                               llvm::Value *state_ptr, llvm::Argument *arg,
                               Operand &arch_op) {
  auto arg_type = arg->getType();
  switch (arch_op.type) {
    case Operand::kTypeInvalid:
      LOG(FATAL) << "Decode error! Cannot lift invalid operand.";
      return nullptr;

    case Operand::kTypeShiftRegister:
      CHECK(Operand::kActionRead == arch_op.action)
          << "Can't write to a shift register operand "
          << "for instruction at " << std::hex << inst.pc;

      return LiftShiftRegisterOperand(inst, block, state_ptr, arg, arch_op);

    case Operand::kTypeRegister:
      if (arch_op.size != arch_op.reg.size) {
        LOG(FATAL) << "Operand size and register size must match for register "
                   << arch_op.reg.name << " in instruction "
                   << inst.Serialize();
      }
      return LiftRegisterOperand(inst, block, state_ptr, arg, arch_op);

    case Operand::kTypeImmediate:
      return LiftImmediateOperand(inst, block, arg, arch_op);

    case Operand::kTypeAddress:
      if (arg_type != word_type) {
        LOG(FATAL) << "Expected that a memory operand should be represented by "
                   << "machine word type. Argument type is "
                   << LLVMThingToString(arg_type) << " and word type is "
                   << LLVMThingToString(word_type) << " in instruction at "
                   << std::hex << inst.pc;
      }

      return LiftAddressOperand(inst, block, state_ptr, arg, arch_op);
  }

  LOG(FATAL) << "Got a unknown operand type of "
             << static_cast<int>(arch_op.type) << " in instruction at "
             << std::hex << inst.pc;

  return nullptr;
}

TraceManager::~TraceManager(void) {}

// Return an already lifted trace starting with the code at address
// `addr`.
llvm::Function *TraceManager::GetLiftedTraceDeclaration(uint64_t) {
  return nullptr;
}

// Return an already lifted trace starting with the code at address
// `addr`.
llvm::Function *TraceManager::GetLiftedTraceDefinition(uint64_t) {
  return nullptr;
}

// Apply a callback that gives the decoder access to multiple virtual
// targets of this instruction (indirect call or jump).
void TraceManager::ForEachDevirtualizedTarget(
    const Instruction &,
    std::function<void(uint64_t, DevirtualizedTargetKind)>) {

  // Must be extended.
}

// Figure out the name for the trace starting at address `addr`.
std::string TraceManager::TraceName(uint64_t addr) {
  std::stringstream ss;
  ss << "sub_" << std::hex << addr;
  return ss.str();
}

namespace {

using DecoderWorkList = std::set<uint64_t>;  // For ordering.

}  // namespace

class TraceLifter::Impl {
 public:
  Impl(InstructionLifter *inst_lifter_, TraceManager *manager_);

  // Lift one or more traces starting from `addr`. Calls `callback` with each
  // lifted trace.
  bool Lift(uint64_t addr,
            std::function<void(uint64_t, llvm::Function *)> callback);

  // Reads the bytes of an instruction at `addr` into `state.inst_bytes`.
  bool ReadInstructionBytes(uint64_t addr);

  // Return an already lifted trace starting with the code at address
  // `addr`.
  //
  // NOTE: This is guaranteed to return either `nullptr`, or a function
  //       within `module`.
  llvm::Function *GetLiftedTraceDeclaration(uint64_t addr);

  // Return an already lifted trace starting with the code at address
  // `addr`.
  //
  // NOTE: This is guaranteed to return either `nullptr`, or a function
  //       within `module`.
  llvm::Function *GetLiftedTraceDefinition(uint64_t addr);

  llvm::BasicBlock *GetOrCreateBlock(uint64_t block_pc) {
    auto &block = blocks[block_pc];
    if (!block) {
      block = llvm::BasicBlock::Create(context, "", func);
    }
    return block;
  }

  llvm::BasicBlock *GetOrCreateBranchTakenBlock(void) {
    inst_work_list.insert(inst.branch_taken_pc);
    return GetOrCreateBlock(inst.branch_taken_pc);
  }

  llvm::BasicBlock *GetOrCreateBranchNotTakenBlock(void) {
    inst_work_list.insert(inst.branch_not_taken_pc);
    return GetOrCreateBlock(inst.branch_not_taken_pc);
  }

  llvm::BasicBlock *GetOrCreateNextBlock(void) {
    inst_work_list.insert(inst.next_pc);
    return GetOrCreateBlock(inst.next_pc);
  }

  uint64_t PopTraceAddress(void) {
    auto trace_it = trace_work_list.begin();
    const auto trace_addr = *trace_it;
    trace_work_list.erase(trace_it);
    return trace_addr;
  }

  uint64_t PopInstructionAddress(void) {
    auto inst_it = inst_work_list.begin();
    const auto inst_addr = *inst_it;
    inst_work_list.erase(inst_it);
    return inst_addr;
  }

  const Arch *const arch;
  InstructionLifter &inst_lifter;
  const remill::IntrinsicTable *intrinsics;
  llvm::LLVMContext &context;
  llvm::Module *const module;
  const uint64_t addr_mask;
  TraceManager &manager;

  llvm::Function *func;
  llvm::BasicBlock *block;
  llvm::SwitchInst *switch_inst;
  const size_t max_inst_bytes;
  std::string inst_bytes;
  Instruction inst;
  Instruction delayed_inst;
  DecoderWorkList trace_work_list;
  DecoderWorkList inst_work_list;
  std::map<uint64_t, llvm::BasicBlock *> blocks;
};

TraceLifter::Impl::Impl(InstructionLifter *inst_lifter_, TraceManager *manager_)
    : arch(inst_lifter_->arch),
      inst_lifter(*inst_lifter_),
      intrinsics(inst_lifter.intrinsics),
      context(inst_lifter.word_type->getContext()),
      module(inst_lifter.intrinsics->async_hyper_call->getParent()),
      addr_mask(~0ULL >> inst_lifter.word_type->getPrimitiveSizeInBits()),
      manager(*manager_),
      func(nullptr),
      block(nullptr),
      switch_inst(nullptr),
      max_inst_bytes(arch->MaxInstructionSize()) {

  inst_bytes.reserve(max_inst_bytes);
}

// Return an already lifted trace starting with the code at address
// `addr`.
llvm::Function *TraceLifter::Impl::GetLiftedTraceDeclaration(uint64_t addr) {
  auto func = manager.GetLiftedTraceDeclaration(addr);
  if (!func || func->getParent() == module) {
    return func;
  }

  return nullptr;
}

// Return an already lifted trace starting with the code at address
// `addr`.
llvm::Function *TraceLifter::Impl::GetLiftedTraceDefinition(uint64_t addr) {
  auto func = manager.GetLiftedTraceDefinition(addr);
  if (!func || func->getParent() == module) {
    return func;
  }

  CHECK_EQ(&(func->getContext()), &context);

  auto func_type = llvm::dyn_cast<llvm::FunctionType>(
      RecontextualizeType(func->getFunctionType(), context));

  // Handle the different module situation by declaring the trace in
  // this module to be external, with the idea that it will link to
  // another module.
  auto extern_func = module->getFunction(func->getName());
  if (!extern_func || extern_func->getFunctionType() != func_type) {
    extern_func = llvm::Function::Create(
        func_type, llvm::GlobalValue::ExternalLinkage, func->getName(), module);

  } else if (extern_func->isDeclaration()) {
    extern_func->setLinkage(llvm::GlobalValue::ExternalLinkage);
  }

  return extern_func;
}

TraceLifter::~TraceLifter(void) {}

TraceLifter::TraceLifter(InstructionLifter *inst_lifter_,
                         TraceManager *manager_)
    : impl(new Impl(inst_lifter_, manager_)) {}

void TraceLifter::NullCallback(uint64_t, llvm::Function *) {}

// Reads the bytes of an instruction at `addr` into `inst_bytes`.
bool TraceLifter::Impl::ReadInstructionBytes(uint64_t addr) {
  inst_bytes.clear();
  for (size_t i = 0; i < max_inst_bytes; ++i) {
    const auto byte_addr = (addr + i) & addr_mask;
    if (byte_addr < addr) {
      break;  // 32- or 64-bit address overflow.
    }
    uint8_t byte = 0;
    if (!manager.TryReadExecutableByte(byte_addr, &byte)) {
      DLOG(WARNING) << "Couldn't read executable byte at " << std::hex
                    << byte_addr << std::dec;
      break;
    }
    inst_bytes.push_back(static_cast<char>(byte));
  }
  return !inst_bytes.empty();
}

// Lift one or more traces starting from `addr`.
bool TraceLifter::Lift(
    uint64_t addr, std::function<void(uint64_t, llvm::Function *)> callback) {
  return impl->Lift(addr, callback);
}

// Lift one or more traces starting from `addr`.
bool TraceLifter::Impl::Lift(
    uint64_t addr_, std::function<void(uint64_t, llvm::Function *)> callback) {
  auto addr = addr_ & addr_mask;
  if (addr < addr_) {  // Address is out of range.
    LOG(ERROR) << "Trace address " << std::hex << addr_ << " is too big"
               << std::dec;
    return false;
  }

  // Reset the lifting state.
  trace_work_list.clear();
  inst_work_list.clear();
  blocks.clear();
  inst_bytes.clear();
  func = nullptr;
  switch_inst = nullptr;
  block = nullptr;
  inst.Reset();
  delayed_inst.Reset();

  // Get a trace head that the manager knows about, or that we
  // will eventually tell the trace manager about.
  auto get_trace_decl = [=](uint64_t addr) -> llvm::Function * {
    if (auto trace = GetLiftedTraceDeclaration(addr)) {
      return trace;
    }

    if (trace_work_list.count(addr)) {
      const auto target_trace_name = manager.TraceName(addr);
      return DeclareLiftedFunction(module, target_trace_name);
    }

    return nullptr;
  };

  trace_work_list.insert(addr);
  while (!trace_work_list.empty()) {
    const auto trace_addr = PopTraceAddress();

    // Already lifted.
    func = GetLiftedTraceDefinition(trace_addr);
    if (func) {
      continue;
    }

    DLOG(INFO) << "Lifting trace at address " << std::hex << trace_addr
               << std::dec;

    func = get_trace_decl(trace_addr);
    blocks.clear();

    if (!func || !func->isDeclaration()) {
      const auto trace_name = manager.TraceName(trace_addr);
      func = DeclareLiftedFunction(module, trace_name);
    }

    CHECK(func->isDeclaration());

    // Fill in the function, and make sure the block with all register
    // variables jumps to the block that will contain the first instruction
    // of the trace.
    CloneBlockFunctionInto(func);
    auto state_ptr = NthArgument(func, kStatePointerArgNum);

    if (auto entry_block = &(func->front())) {
      auto pc = LoadProgramCounterArg(func);
      auto next_pc_ref =
          inst_lifter.LoadRegAddress(entry_block, state_ptr, "NEXT_PC");

      // Initialize `NEXT_PC`.
      (void) new llvm::StoreInst(pc, next_pc_ref, entry_block);

      // Branch to the first basic block.
      llvm::BranchInst::Create(GetOrCreateBlock(trace_addr), entry_block);
    }

    CHECK(inst_work_list.empty());
    inst_work_list.insert(trace_addr);

    // Decode instructions.
    while (!inst_work_list.empty()) {
      const auto inst_addr = PopInstructionAddress();

      block = GetOrCreateBlock(inst_addr);
      switch_inst = nullptr;

      // We have already lifted this instruction block.
      if (!block->empty()) {
        continue;
      }

      // Check to see if this instruction corresponds with an existing
      // trace head, and if so, tail-call into that trace directly without
      // decoding or lifting the instruction.
      if (inst_addr != trace_addr) {
        if (auto inst_as_trace = get_trace_decl(inst_addr)) {
          AddTerminatingTailCall(block, inst_as_trace);
          continue;
        }
      }

      // No executable bytes here.
      if (!ReadInstructionBytes(inst_addr)) {
        AddTerminatingTailCall(block, intrinsics->missing_block);
        continue;
      }

      inst.Reset();

      (void) arch->DecodeInstruction(inst_addr, inst_bytes, inst);

      auto lift_status = inst_lifter.LiftIntoBlock(inst, block, state_ptr);
      if (kLiftedInstruction != lift_status) {
        AddTerminatingTailCall(block, intrinsics->error);
        continue;
      }

      // Handle lifting a delayed instruction.
      auto try_delay = arch->MayHaveDelaySlot(inst);
      if (try_delay) {
        delayed_inst.Reset();
        if (!ReadInstructionBytes(inst.delayed_pc) ||
            !arch->DecodeDelayedInstruction(inst.delayed_pc, inst_bytes,
                                            delayed_inst)) {
          LOG(ERROR) << "Couldn't read delayed inst "
                     << delayed_inst.Serialize();
          AddTerminatingTailCall(block, intrinsics->error);
          continue;
        }
      }

      // Functor used to add in a delayed instruction.
      auto try_add_delay_slot = [&](bool on_branch_taken_path,
                                    llvm::BasicBlock *into_block) -> void {
        if (!try_delay) {
          return;
        }
        if (!arch->NextInstructionIsDelayed(inst, delayed_inst,
                                            on_branch_taken_path)) {
          return;
        }
        lift_status = inst_lifter.LiftIntoBlock(
            delayed_inst, into_block, state_ptr, true /* is_delayed */);
        if (kLiftedInstruction != lift_status) {
          AddTerminatingTailCall(block, intrinsics->error);
        }
      };

      // Connect together the basic blocks.
      switch (inst.category) {
        case Instruction::kCategoryInvalid:
        case Instruction::kCategoryError:
          AddTerminatingTailCall(block, intrinsics->error);
          break;

        case Instruction::kCategoryNormal:
        case Instruction::kCategoryNoOp:
          llvm::BranchInst::Create(GetOrCreateNextBlock(), block);
          break;

        // Direct jumps could either be local or could be tail-calls. In the
        // case of a tail call, we'll assume that the trace manager contains
        // advanced knowledge of this, and so when we go to make a block for
        // the targeted instruction, we'll either tail call to the target
        // trace, or we'll just extend out the current trace. Either way, no
        // sacrifice in correctness is made.
        case Instruction::kCategoryDirectJump:
          try_add_delay_slot(true, block);
          llvm::BranchInst::Create(GetOrCreateBranchTakenBlock(), block);
          break;

        case Instruction::kCategoryIndirectJump: {
          try_add_delay_slot(true, block);

          // The trace manager might know about the targets of things like
          // jump tables, so we will let it tell us about those possibilities.
          std::unordered_map<uint64_t, llvm::BasicBlock *> devirt_targets;
          manager.ForEachDevirtualizedTarget(
              inst,
              [&](uint64_t target_addr, DevirtualizedTargetKind target_kind) {
                if (target_kind == DevirtualizedTargetKind::kTraceHead) {
                  auto target_block =
                      llvm::BasicBlock::Create(context, "", func);
                  devirt_targets[target_addr] = target_block;

                  // Always add to the work list. This will cause us to lift
                  // if we haven't, and guarantee that `get_trace_decl` returns
                  // something.
                  trace_work_list.insert(target_addr);
                  auto target_trace = get_trace_decl(target_addr);
                  AddTerminatingTailCall(target_block, target_trace);

                } else {
                  devirt_targets[target_addr] = GetOrCreateBlock(target_addr);
                  inst_work_list.insert(target_addr);
                }
              });

          if (devirt_targets.empty()) {
            AddTerminatingTailCall(block, intrinsics->jump);
            break;
          }

          auto default_case = llvm::BasicBlock::Create(context, "", func);

          auto pc = LoadProgramCounter(block);
          auto pc_type = pc->getType();
          auto dispatcher = llvm::SwitchInst::Create(
              pc, default_case, devirt_targets.size(), block);
          for (auto devirt_target : devirt_targets) {
            dispatcher->addCase(
                llvm::dyn_cast<llvm::ConstantInt>(llvm::ConstantInt::get(
                    pc_type, devirt_target.first, false)),
                devirt_target.second);
          }
          break;
        }

        case Instruction::kCategoryAsyncHyperCall:
          AddCall(block, intrinsics->async_hyper_call);
          goto check_call_return;

        case Instruction::kCategoryIndirectFunctionCall: {
          try_add_delay_slot(true, block);
          const auto fall_through_block =
              llvm::BasicBlock::Create(context, "", func);

          const auto ret_pc_ref =
              LoadReturnProgramCounterRef(fall_through_block);
          const auto next_pc_ref =
              LoadNextProgramCounterRef(fall_through_block);
          llvm::IRBuilder<> ir(fall_through_block);
          ir.CreateStore(ir.CreateLoad(ret_pc_ref), next_pc_ref);
          ir.CreateBr(GetOrCreateNextBlock());

          // The trace manager might know about the targets of things like
          // virtual tables, so we will let it tell us about those possibilities.
          std::unordered_map<uint64_t, llvm::BasicBlock *> devirt_targets;
          manager.ForEachDevirtualizedTarget(
              inst,
              [&](uint64_t target_addr, DevirtualizedTargetKind target_kind) {
                if (target_kind == DevirtualizedTargetKind::kTraceLocal) {
                  LOG(WARNING)
                      << "Ignoring trace-local target in devirtualizable call";
                  return;
                }

                auto target_block = llvm::BasicBlock::Create(context, "", func);
                devirt_targets[target_addr] = target_block;

                // Always add to the work list. This will cause us to lift
                // if we haven't, and guarantee that `get_trace_decl` returns
                // something.
                trace_work_list.insert(target_addr);
                auto target_trace = get_trace_decl(target_addr);
                AddCall(target_block, target_trace);

                llvm::BranchInst::Create(fall_through_block, target_block);
              });

          if (devirt_targets.empty()) {
            AddCall(block, intrinsics->function_call);
            llvm::BranchInst::Create(fall_through_block, block);
            continue;
          }

          auto default_case = llvm::BasicBlock::Create(context, "", func);
          AddCall(default_case, intrinsics->function_call);
          llvm::BranchInst::Create(fall_through_block, default_case);

          auto pc = LoadProgramCounter(block);
          auto pc_type = pc->getType();
          auto dispatcher = llvm::SwitchInst::Create(
              pc, default_case, devirt_targets.size(), block);
          for (auto devirt_target : devirt_targets) {
            dispatcher->addCase(
                llvm::dyn_cast<llvm::ConstantInt>(llvm::ConstantInt::get(
                    pc_type, devirt_target.first, false)),
                devirt_target.second);
          }

          block = fall_through_block;
          continue;
        }

        // In the case of a direct function call, we try to handle the
        // pattern of a call to the next PC as a way of getting access to
        // an instruction pointer. It is the case where a call to the next
        // PC could also be something more like a call to a `noreturn` function
        // and that is OK, because either a user of the trace manager has
        // already told us that the next PC is a trace head (and we'll pick
        // that up when trying to lift it), or we'll just have a really big
        // trace for this function without sacrificing correctness.
        case Instruction::kCategoryDirectFunctionCall: {
          try_add_delay_slot(true, block);
          if (inst.next_pc != inst.branch_taken_pc) {
            trace_work_list.insert(inst.branch_taken_pc);
            auto target_trace = get_trace_decl(inst.branch_taken_pc);
            AddCall(block, target_trace);
          }

          const auto ret_pc_ref = LoadReturnProgramCounterRef(block);
          const auto next_pc_ref = LoadNextProgramCounterRef(block);
          llvm::IRBuilder<> ir(block);
          ir.CreateStore(ir.CreateLoad(ret_pc_ref), next_pc_ref);
          ir.CreateBr(GetOrCreateNextBlock());

          continue;
        }

        // Lift an async hyper call to check if it should do the hypercall.
        // If so, it will jump to the `do_hyper_call` block, otherwise it will
        // jump to the block associated with the next PC. In the case of the
        // `do_hyper_call` block, we assign it to `state.block`, then go
        // to `check_call_return` to add the hyper call into that block,
        // checking if the hyper call returns to the next PC or not.
        case Instruction::kCategoryConditionalAsyncHyperCall: {
          auto do_hyper_call = llvm::BasicBlock::Create(context, "", func);
          llvm::BranchInst::Create(do_hyper_call, GetOrCreateNextBlock(),
                                   LoadBranchTaken(block), block);
          block = do_hyper_call;
          AddCall(block, intrinsics->async_hyper_call);
          goto check_call_return;
        }

        check_call_return:
          do {
            auto pc = LoadProgramCounter(block);
            auto ret_pc =
                llvm::ConstantInt::get(inst_lifter.word_type, inst.next_pc);

            llvm::IRBuilder<> ir(block);
            auto eq = ir.CreateICmpEQ(pc, ret_pc);
            auto unexpected_ret_pc =
                llvm::BasicBlock::Create(context, "", func);
            ir.CreateCondBr(eq, GetOrCreateNextBlock(), unexpected_ret_pc);
            AddTerminatingTailCall(unexpected_ret_pc,
                                   intrinsics->missing_block);
          } while (false);
          break;

        case Instruction::kCategoryFunctionReturn:
          try_add_delay_slot(true, block);
          AddTerminatingTailCall(block, intrinsics->function_return);
          break;

        case Instruction::kCategoryConditionalBranch: {
          auto taken_block = GetOrCreateBranchTakenBlock();
          auto not_taken_block = GetOrCreateBranchNotTakenBlock();

          // If we might need to add delay slots, then try to lift the delayed
          // instruction on each side of the conditional branch, injecting in
          // new blocks (for the delayed instruction) between the branch
          // and its original targets.
          if (try_delay) {
            auto new_taken_block = llvm::BasicBlock::Create(context, "", func);
            auto new_not_taken_block =
                llvm::BasicBlock::Create(context, "", func);

            try_add_delay_slot(true, new_taken_block);
            try_add_delay_slot(false, new_not_taken_block);

            llvm::BranchInst::Create(taken_block, new_taken_block);
            llvm::BranchInst::Create(not_taken_block, new_not_taken_block);

            taken_block = new_taken_block;
            not_taken_block = new_not_taken_block;
          }

          llvm::BranchInst::Create(taken_block, not_taken_block,
                                   LoadBranchTaken(block), block);
          break;
        }
      }
    }

    for (auto &block : *func) {
      if (!block.getTerminator()) {
        AddTerminatingTailCall(&block, intrinsics->missing_block);
      }
    }

    callback(trace_addr, func);
    manager.SetLiftedTraceDefinition(trace_addr, func);
  }

  return true;
}

}  // namespace remill
