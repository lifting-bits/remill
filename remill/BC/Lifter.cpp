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
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Operator.h>
#include <llvm/IR/Type.h>

#include <llvm/Support/raw_ostream.h>

#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/ValueMapper.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Instruction.h"
#include "remill/Arch/Name.h"

#include "remill/BC/ABI.h"
#include "remill/BC/IntrinsicTable.h"
#include "remill/BC/Lifter.h"
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

InstructionLifter::InstructionLifter(const Arch *arch_,
                                     const IntrinsicTable *intrinsics_)
    : arch(arch_),
      word_type(llvm::Type::getIntNTy(
          intrinsics_->async_hyper_call->getContext(),
          arch->address_size)),
      intrinsics(intrinsics_) {}

// Lift a single instruction into a basic block.
LiftStatus InstructionLifter::LiftIntoBlock(
    Instruction &arch_inst, llvm::BasicBlock *block) {

  llvm::Function *func = block->getParent();
  llvm::Module *module = func->getParent();
  llvm::Function *isel_func = nullptr;
  auto status = kLiftedInstruction;

  if (arch_inst.IsValid()) {
    isel_func = GetInstructionFunction(module, arch_inst.function);
  } else {
    LOG(ERROR)
        << "Cannot decode instruction bytes at "
        << std::hex << arch_inst.pc << std::dec;

    isel_func = GetInstructionFunction(module, "INVALID_INSTRUCTION");
    CHECK(isel_func != nullptr)
        << "INVALID_INSTRUCTION doesn't exist.";

    arch_inst.operands.clear();
    status = kLiftedInvalidInstruction;
  }

  if (!isel_func) {
    LOG(ERROR)
        << "Missing semantics for instruction " << arch_inst.Serialize();

    isel_func = GetInstructionFunction(module, "UNSUPPORTED_INSTRUCTION");
    CHECK(isel_func != nullptr)
        << "UNSUPPORTED_INSTRUCTION doesn't exist; not using it in place of "
        << arch_inst.function;

    arch_inst.operands.clear();
    status = kLiftedUnsupportedInstruction;
  }

  llvm::IRBuilder<> ir(block);
  auto mem_ptr = LoadMemoryPointerRef(block);
  auto state_ptr = LoadStatePointer(block);
  auto pc_ptr = LoadProgramCounterRef(block);

  // Begin an atomic block.
  if (arch_inst.is_atomic_read_modify_write) {
    std::vector<llvm::Value *> args = {ir.CreateLoad(mem_ptr)};
    ir.CreateStore(
        ir.CreateCall(intrinsics->atomic_begin, args),
        mem_ptr);
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
        << isel_func->getName().str() << ", should have at least "
        << arg_num << " arguments for instruction "
        << arch_inst.Serialize();

    auto arg = NthArgument(isel_func, arg_num);
    auto arg_type = arg->getType();
    auto operand = LiftOperand(arch_inst, block, arg, op);
    arg_num += 1;
    auto op_type = operand->getType();
    CHECK(op_type == arg_type)
        << "Lifted operand " << op.Serialize() << " to "
        << arch_inst.function << " does not have the correct type. Expected "
        << LLVMThingToString(arg_type) << " but got "
        << LLVMThingToString(op_type) << ".";

    args.push_back(operand);
  }

  // Update the current program counter. Control-flow instructions may update
  // the program counter in the semantics code.
  ir.CreateStore(
      ir.CreateAdd(
          ir.CreateLoad(pc_ptr),
          llvm::ConstantInt::get(word_type, arch_inst.NumBytes())),
      pc_ptr);

  // Pass in current value of the memory pointer.
  args[0] = ir.CreateLoad(mem_ptr);

  // Call the function that implements the instruction semantics.
  ir.CreateStore(ir.CreateCall(isel_func, args), mem_ptr);

  // End an atomic block.
  if (arch_inst.is_atomic_read_modify_write) {
    std::vector<llvm::Value *> args = {ir.CreateLoad(mem_ptr)};
    ir.CreateStore(
        ir.CreateCall(intrinsics->atomic_end, args),
        mem_ptr);
  }

  return status;
}

namespace {

// Load the address of a register.
static llvm::Value *LoadRegAddress(llvm::BasicBlock *block,
                                   std::string reg_name) {
  return FindVarInFunction(block->getParent(), reg_name);
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

llvm::Value *InstructionLifter::LiftShiftRegisterOperand(
    Instruction &inst, llvm::BasicBlock *block,
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
  auto reg = LoadRegValue(block, arch_reg.name);
  auto reg_type = reg->getType();
  auto reg_size = data_layout.getTypeAllocSizeInBits(reg_type);
  auto word_size = data_layout.getTypeAllocSizeInBits(word_type);
  auto op_type = llvm::Type::getIntNTy(context, op.size);

  const uint64_t zero = 0;
  const uint64_t one = 1;
  const uint64_t shift_size = op.shift_reg.shift_size;

  const auto shift_val = llvm::ConstantInt::get(op_type, shift_size);

  llvm::IRBuilder<> ir(block);

  auto curr_size = reg_size;
  if (Operand::ShiftRegister::kExtendInvalid != op.shift_reg.extend_op) {

    auto extract_type = llvm::Type::getIntNTy(
        context, op.shift_reg.extract_size);

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
          LOG(FATAL)
              << "Invalid extend operation type for instruction at "
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
        const auto mask_val = llvm::ConstantInt::get(
            reg_type, ~((~zero) << shift_size));
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

      case Operand::ShiftRegister::kShiftInvalid:
        break;
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

static llvm::Value *ConvertToIntendedType(Instruction &inst, Operand &op,
                                          llvm::BasicBlock *block,
                                          llvm::Value *val,
                                          llvm::Type *intended_type) {
  auto val_type = val->getType();
  if (val->getType() == intended_type) {
    return val;
  } else if (val_type->isPointerTy()) {
    if (intended_type->isPointerTy()) {
      return new llvm::BitCastInst(val, intended_type, "", block);
    } else if (intended_type->isIntegerTy()) {
      return new llvm::PtrToIntInst(val, intended_type, "", block);
    }
  }

  LOG(FATAL)
      << "Unable to convert value " << LLVMThingToString(val)
      << " to intended argument type " << LLVMThingToString(intended_type)
      << " for operand " << op.Serialize() << " of instruction "
      << inst.Serialize();

  return nullptr;
}

}  // namespace

// Load a register operand. This deals uniformly with write- and read-operands
// for registers. In the case of write operands, the argument type is always
// a pointer. In the case of read operands, the argument type is sometimes
// a pointer (e.g. when passing a vector to an instruction semantics function).
llvm::Value *InstructionLifter::LiftRegisterOperand(
    Instruction &inst, llvm::BasicBlock *block,
    llvm::Argument *arg, Operand &op) {

  llvm::Function *func = block->getParent();
  llvm::Module *module = func->getParent();
  auto &arch_reg = op.reg;

  const auto real_arg_type = arg->getType();
  auto arg_type = real_arg_type;

  // LLVM on AArch64 converts things like `RnW<uint64_t>`, which is a struct
  // containing a `uint64_t *`, into a `uintptr_t` when they are being passed
  // as arguments.
  if (arg_type->isIntegerTy() && GetHostArch()->IsAArch64()) {
    arg_type = IntendedArgumentType(arg);
  }

  if (llvm::isa<llvm::PointerType>(arg_type)) {
    auto val = LoadRegAddress(block, arch_reg.name);
    return ConvertToIntendedType(inst, op, block, val, real_arg_type);

  } else {
    CHECK(arg_type->isIntegerTy() || arg_type->isFloatingPointTy())
        << "Expected " << arch_reg.name << " to be an integral or float type "
        << "for instruction at " << std::hex << inst.pc;

    auto val = LoadRegValue(block, arch_reg.name);

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
llvm::Value *InstructionLifter::LiftImmediateOperand(Instruction &inst,
                                                     llvm::BasicBlock *,
                                                     llvm::Argument *arg,
                                                     Operand &arch_op) {
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

    return llvm::ConstantInt::get(
        arg_type, arch_op.imm.val, arch_op.imm.is_signed);

  } else {
    CHECK(arg_type->isIntegerTy(word_type->getBitWidth()))
        << "Bad semantics function implementation for instruction at "
        << std::hex << inst.pc << ". Integer constants that are "
        << "smaller than the machine word size should be represented as "
        << "machine word sized arguments to semantics functions.";

    return llvm::ConstantInt::get(
        word_type, arch_op.imm.val, arch_op.imm.is_signed);
  }
}

// Zero-extend a value to be the machine word size.
llvm::Value *InstructionLifter::LiftAddressOperand(
    Instruction &inst, llvm::BasicBlock *block, llvm::Argument *, Operand &op) {
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
llvm::Value *InstructionLifter::LiftOperand(Instruction &inst,
                                            llvm::BasicBlock *block,
                                            llvm::Argument *arg,
                                            Operand &arch_op) {
  auto arg_type = arg->getType();
  switch (arch_op.type) {
    case Operand::kTypeInvalid:
      LOG(FATAL)
          << "Decode error! Cannot lift invalid operand.";
      return nullptr;

    case Operand::kTypeShiftRegister:
      CHECK(Operand::kActionRead == arch_op.action)
          << "Can't write to a shift register operand "
          << "for instruction at " << std::hex << inst.pc;

      return LiftShiftRegisterOperand(inst, block, arg, arch_op);

    case Operand::kTypeRegister:
      if (arch_op.size != arch_op.reg.size) {
        LOG(FATAL)
            << "Operand size and register size must match for register "
            << arch_op.reg.name << " in instruction " << inst.Serialize();
      }
      return LiftRegisterOperand(inst, block, arg, arch_op);

    case Operand::kTypeImmediate:
      return LiftImmediateOperand(inst, block, arg, arch_op);

    case Operand::kTypeAddress:
      if (arg_type != word_type) {
        LOG(FATAL)
            << "Expected that a memory operand should be represented by "
            << "machine word type. Argument type is "
            << LLVMThingToString(arg_type) << " and word type is "
            << LLVMThingToString(word_type) << " in instruction at "
            << std::hex << inst.pc;
      }

      return LiftAddressOperand(inst, block, arg, arch_op);
  }

  LOG(FATAL)
      << "Got a unknown operand type of " << static_cast<int>(arch_op.type)
      << " in instruction at " << std::hex << inst.pc;

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

TraceLifter::TraceLifter(InstructionLifter *inst_lifter_,
                         TraceManager *manager_)
    : arch(inst_lifter_->arch),
      inst_lifter(*inst_lifter_),
      intrinsics(inst_lifter.intrinsics),
      context(inst_lifter.word_type->getContext()),
      module(inst_lifter.intrinsics->async_hyper_call->getParent()),
      addr_mask(~0ULL >> inst_lifter.word_type->getScalarSizeInBits()),
      manager(*manager_) {}

// Return an already lifted trace starting with the code at address
// `addr`.
llvm::Function *TraceLifter::GetLiftedTraceDeclaration(uint64_t addr) {
  auto func = manager.GetLiftedTraceDeclaration(addr);
  if (!func || func->getParent() == module) {
    return func;
  }

  return nullptr;
}

// Return an already lifted trace starting with the code at address
// `addr`.
llvm::Function *TraceLifter::GetLiftedTraceDefinition(uint64_t addr) {
  auto func = manager.GetLiftedTraceDefinition(addr);
  if (!func || func->getParent() == module) {
    return func;
  }

  CHECK(&(func->getContext()) == &context);

  auto extern_func = DeclareLiftedFunction(module, func->getName().str());
  if (extern_func->isDeclaration()) {
    extern_func->setLinkage(llvm::GlobalValue::ExternalLinkage);
  }

  return extern_func;
}

namespace {

using DecoderWorkList = std::set<uint64_t>;

// Manage decoding and lifting state.
//
// This is pretty ugly, it's like a big bag of poorly structured state. The
// actual `Lift` method was getting out of hand.
struct TraceLifterState {
 public:
  TraceLifterState(const Arch *arch, llvm::Module *module_)
      : context(module_->getContext()),
        module(module_),
        func(nullptr),
        block(nullptr),
        switch_inst(nullptr),
        max_inst_bytes(arch->MaxInstructionSize()) {

    inst_bytes.reserve(max_inst_bytes);
  }

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

  llvm::LLVMContext &context;
  llvm::Module * const module;
  llvm::Function *func;
  llvm::BasicBlock *block;
  llvm::SwitchInst *switch_inst;
  const size_t max_inst_bytes;
  std::string inst_bytes;
  Instruction inst;
  DecoderWorkList trace_work_list;
  DecoderWorkList inst_work_list;
  std::map<uint64_t, llvm::BasicBlock *> blocks;
};

}  // namespace

void TraceLifter::NullCallback(uint64_t, llvm::Function *) {}

// Lift one or more traces starting from `addr`.
bool TraceLifter::Lift(uint64_t addr_,
                       std::function<void(uint64_t,llvm::Function *)> callback) {
  auto addr = addr_ & addr_mask;
  if (addr < addr_) {  // Address is out of range.
    LOG(ERROR)
        << "Trace address " << std::hex << addr_ << " is too big" << std::dec;
    return false;
  }

  TraceLifterState state(arch, module);

  state.trace_work_list.insert(addr);
  while (!state.trace_work_list.empty()) {
    const auto trace_addr = state.PopTraceAddress();

    // Already lifted.
    state.func = GetLiftedTraceDefinition(trace_addr);
    if (state.func) {
      continue;
    }

    DLOG(INFO)
        << "Lifting trace at address " << std::hex << trace_addr << std::dec;

    state.func = GetLiftedTraceDeclaration(trace_addr);
    state.blocks.clear();

    if (!state.func) {
      const auto trace_name = manager.TraceName(trace_addr);
      state.func = DeclareLiftedFunction(module, trace_name);
    }

    CHECK(state.func->isDeclaration());

    // Fill in the function, and make sure the block with all register
    // variables jumps to the block that will contain the first instruction
    // of the trace.
    CloneBlockFunctionInto(state.func);
    llvm::BranchInst::Create(state.GetOrCreateBlock(trace_addr),
                             &(state.func->front()));

    CHECK(state.inst_work_list.empty());
    state.inst_work_list.insert(trace_addr);

    llvm::Function *target_trace = nullptr;

    // Decode instructions.
    while (!state.inst_work_list.empty()) {
      const auto inst_addr = state.PopInstructionAddress();

      state.block = state.GetOrCreateBlock(inst_addr);
      state.switch_inst = nullptr;

      // We have already lifted this instruction block.
      if (!state.block->empty()) {
        continue;
      }

      // Check to see if this instruction corresponds with an existing
      // trace head, and if so, tail-call into that trace directly without
      // decoding or lifting the instruction.
      if (inst_addr != trace_addr) {
        if (auto inst_as_trace = GetLiftedTraceDeclaration(inst_addr)) {
          AddTerminatingTailCall(state.block, inst_as_trace);
          continue;
        }
      }

      // Read instruction bytes.
      state.inst_bytes.clear();
      for (size_t i = 0; i < state.max_inst_bytes; ++i) {
        const auto byte_addr = (inst_addr + i) & addr_mask;
        if (byte_addr < inst_addr) {
          break;  // 32- or 64-bit address overflow.
        }
        uint8_t byte = 0;
        if (!manager.TryReadExecutableByte(byte_addr, &byte)) {
          DLOG(WARNING)
              << "Couldn't read executable byte at "
              << std::hex << byte_addr << std::dec;
          break;
        }
        state.inst_bytes.push_back(static_cast<char>(byte));
      }

      // No executable bytes here.
      if (state.inst_bytes.empty()) {
        AddTerminatingTailCall(state.block, intrinsics->missing_block);
        continue;
      }

      state.inst.Reset();

      (void) arch->DecodeInstruction(inst_addr, state.inst_bytes, state.inst);

      auto lift_status = inst_lifter.LiftIntoBlock(state.inst, state.block);
      if (kLiftedInstruction != lift_status) {
        AddTerminatingTailCall(state.block, intrinsics->error);
        continue;
      }

      // Connect together the basic blocks.
      switch (state.inst.category) {
        case Instruction::kCategoryInvalid:
        case Instruction::kCategoryError:
          AddTerminatingTailCall(state.block, intrinsics->error);
          break;

        case Instruction::kCategoryNormal:
        case Instruction::kCategoryNoOp:
          llvm::BranchInst::Create(state.GetOrCreateNextBlock(),
                                   state.block);
          break;

        // Direct jumps could either be local or could be tail-calls. In the
        // case of a tail call, we'll assume that the trace manager contains
        // advanced knowledge of this, and so when we go to make a block for
        // the targeted instruction, we'll either tail call to the target
        // trace, or we'll just extend out the current trace. Either way, no
        // sacrifice in correctness is made.
        case Instruction::kCategoryDirectJump:
          llvm::BranchInst::Create(state.GetOrCreateBranchTakenBlock(),
                                   state.block);
          break;

        case Instruction::kCategoryIndirectJump:
          // TODO(pag): Handle target devirtualization.
          AddTerminatingTailCall(state.block, intrinsics->jump);
          break;

        case Instruction::kCategoryAsyncHyperCall:
          target_trace = intrinsics->async_hyper_call;
          goto check_call_return;

        case Instruction::kCategoryIndirectFunctionCall:
          // TODO(pag): Handle target devirtualization.
          target_trace = intrinsics->function_call;
          goto check_call_return;

        // In the case of a direct function call, we try to handle the
        // pattern of a call to the next PC as a way of getting access to
        // an instruction pointer. It is the case where a call to the next
        // PC could also be something more like a call to a `noreturn` function
        // and that is OK, because either a user of the trace manager has
        // already told us that the next PC is a trace head (and we'll pick
        // that up when trying to lift it), or we'll just have a really big
        // trace for this function without sacrificing correctness.
        case Instruction::kCategoryDirectFunctionCall:
          if (state.inst.next_pc == state.inst.branch_taken_pc) {
            llvm::BranchInst::Create(state.GetOrCreateNextBlock(),
                                     state.block);
            continue;
          }

          target_trace = GetLiftedTraceDeclaration(
              state.inst.branch_taken_pc);

          if (!target_trace) {
            state.trace_work_list.insert(state.inst.branch_taken_pc);
            const auto target_trace_name = manager.TraceName(
                state.inst.branch_taken_pc);
            target_trace = DeclareLiftedFunction(module, target_trace_name);
          }

          goto check_call_return;

        // Lift an async hyper call to check if it should do the hypercall.
        // If so, it will jump to the `do_hyper_call` block, otherwise it will
        // jump to the block associated with the next PC. In the case of the
        // `do_hyper_call` block, we assign it to `state.block`, then go
        // to `check_call_return` to add the hyper call into that block,
        // checking if the hyper call returns to the next PC or not.
        case Instruction::kCategoryConditionalAsyncHyperCall: {
          auto do_hyper_call = llvm::BasicBlock::Create(
              context, "", state.func);
          llvm::BranchInst::Create(
              do_hyper_call,
              state.GetOrCreateNextBlock(),
              LoadBranchTaken(state.block),
              state.block);
          state.block = do_hyper_call;
          target_trace = intrinsics->async_hyper_call;
          goto check_call_return;
        }

        check_call_return: {
          AddCall(state.block, target_trace);

          auto pc = LoadProgramCounter(state.block);
          auto ret_pc = llvm::ConstantInt::get(
              inst_lifter.word_type, state.inst.next_pc);

          llvm::IRBuilder<> ir(state.block);
          auto eq = ir.CreateICmpEQ(pc, ret_pc);
          auto unexpected_ret_pc = llvm::BasicBlock::Create(
              context, "", state.func);
          ir.CreateCondBr(eq, state.GetOrCreateNextBlock(), unexpected_ret_pc);
          AddTerminatingTailCall(unexpected_ret_pc, intrinsics->missing_block);
          break;
        }

        case Instruction::kCategoryFunctionReturn:
          AddTerminatingTailCall(state.block, intrinsics->function_return);
          break;

        case Instruction::kCategoryConditionalBranch:
          llvm::BranchInst::Create(
              state.GetOrCreateBranchTakenBlock(),
              state.GetOrCreateBranchNotTakenBlock(),
              LoadBranchTaken(state.block),
              state.block);
          break;
      }
    }

    for (auto &block : *state.func) {
      if (!block.getTerminator()) {
        AddTerminatingTailCall(&block, intrinsics->missing_block);
      }
    }

    callback(trace_addr, state.func);
    manager.SetLiftedTraceDefinition(trace_addr, state.func);
  }

  return true;
}

}  // namespace remill
