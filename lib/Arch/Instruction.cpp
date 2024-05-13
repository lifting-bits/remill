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

#include "remill/Arch/Instruction.h"

#include <glog/logging.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>

#include <iomanip>
#include <sstream>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Name.h"
#include "remill/BC/Util.h"

namespace remill {

std::string OperandExpression::Serialize(void) const {
  std::stringstream ss;
  if (auto llvm_op = std::get_if<LLVMOpExpr>(this)) {
    ss << "(" << llvm::Instruction::getOpcodeName(llvm_op->llvm_opcode) << " "
       << llvm_op->op1->Serialize();
    if (llvm_op->op2) {
      ss << " " << llvm_op->op2->Serialize();
    } else {
      ss << " to " << remill::LLVMThingToString(type);
    }
    ss << ")";
  } else if (auto reg_op = std::get_if<const Register *>(this)) {
    ss << (*reg_op)->name;
  } else if (auto ci_op = std::get_if<llvm::Constant *>(this)) {
    ss << remill::LLVMThingToString(*ci_op);
  } else if (auto str_op = std::get_if<std::string>(this)) {
    ss << *str_op;
  }
  return ss.str();
}

Operand::Register::Register(void) : size(0) {}

Operand::ShiftRegister::ShiftRegister(void)
    : shift_size(0),
      extract_size(0),
      shift_first(false),
      shift_op(Operand::ShiftRegister::kShiftInvalid),
      extend_op(Operand::ShiftRegister::kExtendInvalid) {}

Operand::Immediate::Immediate(void) : val(0), is_signed(false) {}

Operand::Address::Address(void)
    : scale(0),
      displacement(0),
      address_size(0),
      kind(kInvalid) {}

Operand::Operand(void)
    : type(Operand::kTypeInvalid),
      action(Operand::kActionInvalid),
      size(0),
      expr(nullptr) {}

namespace {
static int64_t SignedImmediate(uint64_t val, uint64_t size) {
  switch (size) {
    case 8: return static_cast<int64_t>(static_cast<int8_t>(val));
    case 16: return static_cast<int64_t>(static_cast<int16_t>(val));
    case 32: return static_cast<int64_t>(static_cast<int32_t>(val));
    default: return static_cast<int64_t>(val);
  }
}
}  // namespace

std::string Operand::Serialize(void) const {
  std::stringstream ss;
  switch (action) {
    case Operand::kActionInvalid: ss << "(INVALID_OP "; break;
    case Operand::kActionRead: ss << "(READ_OP "; break;
    case Operand::kActionWrite: ss << "(WRITE_OP "; break;
  }
  switch (type) {
    case Operand::kTypeInvalid: ss << "(INVALID)"; break;

    case Operand::kTypeRegister:
      ss << "(REG_" << reg.size << " " << reg.name << ")";
      break;

    case Operand::kTypeShiftRegister: {
      auto shift_begin = [&](void) {
        switch (shift_reg.shift_op) {
          case Operand::ShiftRegister::kShiftInvalid: break;

          case Operand::ShiftRegister::kShiftLeftWithZeroes:
            ss << "(LSL ";
            break;

          case Operand::ShiftRegister::kShiftLeftWithOnes: ss << "(MSL "; break;

          case Operand::ShiftRegister::kShiftUnsignedRight:
            ss << "(LSR ";
            break;

          case Operand::ShiftRegister::kShiftSignedRight: ss << "(ASR "; break;

          case Operand::ShiftRegister::kShiftLeftAround: ss << "(ROL "; break;

          case Operand::ShiftRegister::kShiftRightAround: ss << "(ROR "; break;
        }
      };

      auto shift_end = [&](void) {
        if (Operand::ShiftRegister::kShiftInvalid != shift_reg.shift_op) {
          ss << " " << shift_reg.shift_size << ")";
        }
      };

      auto extract_begin = [&](void) {
        switch (shift_reg.extend_op) {
          case Operand::ShiftRegister::kExtendInvalid: break;

          case Operand::ShiftRegister::kExtendSigned:
            ss << "(SEXT (TRUNC ";
            break;

          case Operand::ShiftRegister::kExtendUnsigned:
            ss << "(ZEXT (TRUNC ";
            break;
        }
      };

      auto extract_end = [&](void) {
        switch (shift_reg.extend_op) {
          case Operand::ShiftRegister::kExtendInvalid: break;

          case Operand::ShiftRegister::kExtendSigned:
            ss << " " << shift_reg.extract_size << ") " << size << ")";
            break;

          case Operand::ShiftRegister::kExtendUnsigned:
            ss << " " << shift_reg.extract_size << ") " << size << ")";
            break;
        }
      };

      if (shift_reg.shift_first) {
        extract_begin();
        shift_begin();
      } else {
        shift_begin();
        extract_begin();
      }

      ss << "(REG_" << shift_reg.reg.size << " " << shift_reg.reg.name << ")";

      if (shift_reg.shift_first) {
        shift_end();
        extract_end();
      } else {
        extract_end();
        shift_end();
      }

      break;
    }
    case Operand::kTypeImmediate:
      ss << "(";
      if (imm.is_signed) {
        ss << "SIGNED_IMM_" << size << " ";
        auto simm = SignedImmediate(imm.val, size);
        if (simm < 0) {
          ss << "-0x" << std::hex << static_cast<uint64_t>(-simm) << std::dec;
        } else {
          ss << "0x" << std::hex << imm.val << std::dec;
        }
      } else {
        ss << "IMM_" << size << " " << std::hex << imm.val << std::dec << ")";
      }
      break;

    case Operand::kTypeAddress: {
      ss << "(";

      // Nice version of the memory size.
      switch (size) {
        case 8: ss << "BYTE"; break;
        case 16: ss << "WORD"; break;
        case 32: ss << "DWORD"; break;
        case 64: ss << "QWORD"; break;
        case 80: ss << "TBYTE"; break;
        case 128: ss << "OWORD"; break;
        case 256: ss << "DOWORD"; break;
        case 512: ss << "QOWORD"; break;
        default:
          CHECK(!(size & 7))
              << "Memory operand size must be divisible by 8; got " << size
              << " bits.";
          ss << std::dec << (size / 8) << "_BYTES";
          break;
      }

      ss << "_PTR";

      int num_components = 0;
      if (addr.displacement) {
        ++num_components;
      }
      if (!addr.segment_base_reg.name.empty()) {
        ++num_components;
      }
      if (!addr.base_reg.name.empty()) {
        ++num_components;
      }
      if (!addr.index_reg.name.empty()) {
        ++num_components;
      }

      if (1 < num_components) {
        ss << " (ADD";
      }

      if (!addr.segment_base_reg.name.empty()) {
        ss << " (REG_" << addr.segment_base_reg.size << " "
           << addr.segment_base_reg.name << ")";
      }

      if (!addr.base_reg.name.empty()) {
        ss << " (REG_" << addr.base_reg.size << " " << addr.base_reg.name
           << ")";
      }

      if (addr.scale) {
        CHECK(!addr.index_reg.name.empty());
        ss << " (MUL";
      }

      if (!addr.index_reg.name.empty()) {
        ss << " (REG_" << addr.index_reg.size << " " << addr.index_reg.name
           << ")";
      }

      if (addr.scale) {
        ss << " (IMM_" << addr.index_reg.size << " 0x" << std::hex << addr.scale
           << std::dec << ")";
        ss << ")";  // End of `(MUL`.
      }

      if (addr.displacement) {
        ss << " (SIGNED_IMM_" << addr.address_size << " ";
        if (0 > addr.displacement) {
          ss << "-0x" << std::hex << (-addr.displacement) << std::dec;
        } else {
          ss << "0x" << std::hex << addr.displacement << std::dec;
        }
        ss << ")";  // End of `(SIGNED_IMM_`.
      }
      if (1 < num_components) {
        ss << ")";  // End of `(ADD`.
      }
      ss << ")";  // End of `(ADDR_`.
      break;
    }
    case Operand::kTypeExpression:
    case Operand::kTypeRegisterExpression:
    case Operand::kTypeImmediateExpression:
    case Operand::kTypeAddressExpression: ss << expr->Serialize(); break;
  }
  ss << ")";
  return ss.str();
}

std::string Condition::Serialize(void) const {
  std::stringstream ss;

  ss << "(";
  switch (kind) {
    case Condition::kTypeIsEqual:
      ss << "(REG_" << lhs_reg.size << " " << lhs_reg.name << ") = (REG_"
         << rhs_reg.size << " " << rhs_reg.name << ")";
      break;
    case Condition::kTypeIsOne:
      ss << "(REG_" << lhs_reg.size << " " << lhs_reg.name << ") = 1";
      break;
    case Condition::kTypeIsZero:
      ss << "(REG_" << lhs_reg.size << " " << lhs_reg.name << ") = 0";
      break;
    case Condition::kTypeTrue: ss << "TRUE"; break;
  }
  return ss.str();
}


Instruction::Instruction(void)
    : pc(0),
      next_pc(0),
      delayed_pc(0),
      branch_taken_pc(0),
      branch_not_taken_pc(0),
      arch_name(kArchInvalid),
      sub_arch_name(kArchInvalid),
      branch_taken_arch_name(kArchInvalid),
      arch(nullptr),
      is_atomic_read_modify_write(false),
      has_branch_taken_delay_slot(false),
      has_branch_not_taken_delay_slot(false),
      in_delay_slot(false),
      category(Instruction::kCategoryInvalid),
      flows(Instruction::InvalidInsn()) {}

void Instruction::Reset(void) {
  pc = 0;
  next_pc = 0;
  delayed_pc = 0;
  branch_taken_pc = 0;
  branch_not_taken_pc = 0;
  arch_name = kArchInvalid;
  sub_arch_name = kArchInvalid;
  branch_taken_arch_name = kArchInvalid;
  is_atomic_read_modify_write = false;
  has_branch_taken_delay_slot = false;
  has_branch_not_taken_delay_slot = false;
  in_delay_slot = false;
  category = Instruction::kCategoryInvalid;
  arch = nullptr;
  operands.clear();
  function.clear();
  bytes.clear();
  next_expr_index = 0;
}

OperandExpression *Instruction::AllocateExpression(void) {
  CHECK_LT(next_expr_index, kMaxNumExpr);
  return &(exprs[next_expr_index++]);
}

OperandExpression *Instruction::EmplaceRegister(const Register *reg) {
  auto expr = AllocateExpression();
  expr->emplace<const Register *>(reg);
  expr->type = reg->type;
  return expr;
}

OperandExpression *Instruction::EmplaceRegister(std::string_view reg_name) {
  return EmplaceRegister(arch->RegisterByName(reg_name));
}

OperandExpression *Instruction::EmplaceConstant(llvm::Constant *val) {
  auto expr = AllocateExpression();
  expr->emplace<llvm::Constant *>(val);
  expr->type = val->getType();
  return expr;
}

OperandExpression *Instruction::EmplaceVariable(std::string_view var_name,
                                                llvm::Type *type) {
  auto expr = AllocateExpression();
  expr->emplace<std::string>(var_name.data(), var_name.size());
  expr->type = type;
  return expr;
}

OperandExpression *Instruction::EmplaceBinaryOp(unsigned opcode,
                                                OperandExpression *op1,
                                                OperandExpression *op2) {
  auto expr = AllocateExpression();
  expr->emplace<LLVMOpExpr>(LLVMOpExpr{opcode, op1, op2});
  expr->type = op1->type;
  return expr;
}

OperandExpression *Instruction::EmplaceUnaryOp(unsigned opcode,
                                               OperandExpression *op1,
                                               llvm::Type *type) {
  auto expr = AllocateExpression();
  expr->emplace<LLVMOpExpr>(LLVMOpExpr{opcode, op1, nullptr});
  expr->type = type;
  return expr;
}

Operand &Instruction::EmplaceOperand(const Operand::Register &reg_op) {
  operands.emplace_back();
  auto &op = operands.back();
  op.type = Operand::kTypeRegisterExpression;
  op.size = reg_op.size;
  op.reg.name = reg_op.name;
  if (auto reg = arch->RegisterByName(reg_op.name)) {
    op.expr = EmplaceRegister(reg);
  } else {
    auto &context = *arch->context;
    auto ty = llvm::Type::getIntNTy(context, reg_op.size);
    op.expr = EmplaceVariable(reg_op.name, ty);
  }
  return op;
}

Operand &Instruction::EmplaceOperand(const Operand::Immediate &imm_op) {
  operands.emplace_back();
  auto &op = operands.back();
  auto &context = *arch->context;

  auto ty = llvm::Type::getIntNTy(context, arch->address_size);
  op.expr =
      EmplaceConstant(llvm::ConstantInt::get(ty, imm_op.val, imm_op.is_signed));
  op.size = arch->address_size;
  op.type = Operand::kTypeImmediateExpression;
  return op;
}

Operand &Instruction::EmplaceOperand(const Operand::ShiftRegister &shift_op) {
  operands.emplace_back();
  auto &op = operands.back();
  op.type = Operand::kTypeExpression;
  op.size = arch->address_size;
  auto &arch_reg = shift_op.reg;

  auto &context = *arch->context;
  auto reg = arch->RegisterByName(arch_reg.name);
  auto reg_type = reg->type;
  auto reg_size = reg->size * 8u;
  auto op_type = llvm::Type::getIntNTy(context, op.size);

  const uint64_t zero = 0;
  const uint64_t one = 1;
  const uint64_t shift_size = shift_op.shift_size;

  const auto shift_val = llvm::ConstantInt::get(op_type, shift_size);

  auto expr = EmplaceRegister(reg);

  auto curr_size = reg_size;

  auto do_extract = [&](void) {
    if (Operand::ShiftRegister::kExtendInvalid != shift_op.extend_op) {

      auto extract_type = llvm::Type::getIntNTy(context, shift_op.extract_size);

      if (reg_size > shift_op.extract_size) {
        curr_size = shift_op.extract_size;
        expr = EmplaceUnaryOp(llvm::Instruction::Trunc, expr, extract_type);

      } else {
        CHECK(reg_size == shift_op.extract_size)
            << "Invalid extraction size. Can't extract "
            << shift_op.extract_size << " bits from a " << reg_size
            << "-bit value in operand " << op.Serialize()
            << " of instruction at " << std::hex << pc;
      }

      if (op.size > shift_op.extract_size) {
        switch (shift_op.extend_op) {
          case Operand::ShiftRegister::kExtendSigned:
            expr = EmplaceUnaryOp(llvm::Instruction::SExt, expr, op_type);
            curr_size = op.size;
            break;
          case Operand::ShiftRegister::kExtendUnsigned:
            expr = EmplaceUnaryOp(llvm::Instruction::ZExt, expr, op_type);
            curr_size = op.size;
            break;
          default:
            LOG(FATAL) << "Invalid extend operation type for instruction at "
                       << std::hex << pc;
            break;
        }
      }
    }
    CHECK(curr_size <= op.size);

    if (curr_size < op.size) {
      expr = EmplaceUnaryOp(llvm::Instruction::ZExt, expr, op_type);
      curr_size = op.size;
    }
  };

  auto do_shift = [&](void) {
    if (Operand::ShiftRegister::kShiftInvalid != shift_op.shift_op) {

      // Shift size must be smaller than the op size or, for special cases in
      // AArch32, it <= register size. This is used when using LSR/ASR
      // to shift a register value into the carry out operands.
      // for example: andseq r3, sl, r0, lsr #32
      CHECK(shift_size < op.size ||
            (shift_size <= op.size && arch_name == kArchAArch32LittleEndian &&
             shift_op.can_shift_op_size))
          << "Shift of size " << shift_size
          << " is wider than the base register size in shift register in "
          << Serialize();

      switch (shift_op.shift_op) {

        // Left shift.
        case Operand::ShiftRegister::kShiftLeftWithZeroes:
          expr = EmplaceBinaryOp(llvm::Instruction::Shl, expr,
                                 EmplaceConstant(shift_val));
          break;

        // Masking shift left.
        case Operand::ShiftRegister::kShiftLeftWithOnes: {
          const auto mask_val =
              llvm::ConstantInt::get(reg_type, ~((~zero) << shift_size));
          expr = EmplaceBinaryOp(llvm::Instruction::Shl, expr,
                                 EmplaceConstant(shift_val));
          expr = EmplaceBinaryOp(llvm::Instruction::Or, expr,
                                 EmplaceConstant(mask_val));
          break;
        }

        // Logical right shift.
        case Operand::ShiftRegister::kShiftUnsignedRight:
          expr = EmplaceBinaryOp(llvm::Instruction::LShr, expr,
                                 EmplaceConstant(shift_val));
          break;

        // Arithmetic right shift.
        case Operand::ShiftRegister::kShiftSignedRight:
          expr = EmplaceBinaryOp(llvm::Instruction::AShr, expr,
                                 EmplaceConstant(shift_val));
          break;

        // Rotate left.
        case Operand::ShiftRegister::kShiftLeftAround: {
          const uint64_t shr_amount = (~shift_size + one) & (op.size - one);
          const auto shr_val = llvm::ConstantInt::get(op_type, shr_amount);
          auto expr1 = EmplaceBinaryOp(llvm::Instruction::LShr, expr,
                                       EmplaceConstant(shr_val));
          auto expr2 = EmplaceBinaryOp(llvm::Instruction::Shl, expr,
                                       EmplaceConstant(shift_val));
          expr = EmplaceBinaryOp(llvm::Instruction::Or, expr1, expr2);
          break;
        }

        // Rotate right.
        case Operand::ShiftRegister::kShiftRightAround: {
          const uint64_t shl_amount = (~shift_size + one) & (op.size - one);
          const auto shl_val = llvm::ConstantInt::get(op_type, shl_amount);
          auto expr1 = EmplaceBinaryOp(llvm::Instruction::LShr, expr,
                                       EmplaceConstant(shift_val));
          auto expr2 = EmplaceBinaryOp(llvm::Instruction::Shl, expr,
                                       EmplaceConstant(shl_val));
          expr = EmplaceBinaryOp(llvm::Instruction::Or, expr1, expr2);
          break;
        }

        case Operand::ShiftRegister::kShiftInvalid: break;
      }
    }
    if (curr_size < op.size) {
      expr = EmplaceUnaryOp(llvm::Instruction::ZExt, expr, op_type);
      curr_size = op.size;
    }
  };

  if (shift_op.shift_first) {
    do_shift();
    do_extract();
  } else {
    do_extract();
    do_shift();
  }
  op.expr = expr;
  return op;
}

Operand &Instruction::EmplaceOperand(const Operand::Address &addr_op) {
  operands.emplace_back();
  auto &op = operands.back();

  const auto word_type = arch->AddressType();
  const auto zero = llvm::ConstantInt::get(word_type, 0, false);
  const auto word_size = arch->address_size;

  CHECK(word_size >= addr_op.base_reg.size)
      << "Memory base register " << addr_op.base_reg.name
      << "for instruction at " << std::hex << pc
      << " is wider than the machine word size.";

  CHECK(word_size >= addr_op.index_reg.size)
      << "Memory index register " << addr_op.base_reg.name
      << "for instruction at " << std::hex << pc
      << " is wider than the machine word size.";

  auto reg_or_zero = [=](const Operand::Register &reg) {
    if (!reg.name.empty()) {
      if (auto reg_pointer = arch->RegisterByName(reg.name)) {
        return EmplaceRegister(reg_pointer);
      } else {
        return EmplaceVariable(reg.name,
                               llvm::Type::getIntNTy(*arch->context, reg.size));
      }
    } else {
      return EmplaceConstant(zero);
    }
  };

  auto addr = reg_or_zero(addr_op.base_reg);

  if (!addr_op.index_reg.name.empty() && addr_op.scale) {
    auto index = reg_or_zero(addr_op.index_reg);
    if (addr_op.scale != 1) {
      auto scale = llvm::ConstantInt::get(
          word_type, static_cast<uint64_t>(addr_op.scale), true);
      index = EmplaceBinaryOp(llvm::Instruction::Mul, index,
                              EmplaceConstant(scale));
    }
    addr = EmplaceBinaryOp(llvm::Instruction::Add, addr, index);
  }

  if (addr_op.displacement) {
    if (0 < addr_op.displacement) {
      auto disp = llvm::ConstantInt::get(
          word_type, static_cast<uint64_t>(addr_op.displacement));
      addr =
          EmplaceBinaryOp(llvm::Instruction::Add, addr, EmplaceConstant(disp));
    } else {
      auto disp = llvm::ConstantInt::get(
          word_type, static_cast<uint64_t>(-addr_op.displacement));
      addr =
          EmplaceBinaryOp(llvm::Instruction::Sub, addr, EmplaceConstant(disp));
    }
  }

  // Compute the segmented address.
  if (!addr_op.segment_base_reg.name.empty()) {
    auto segment = reg_or_zero(addr_op.segment_base_reg);
    addr = EmplaceBinaryOp(llvm::Instruction::Add, addr, segment);
  }

  // Memory address is smaller than the machine word size (e.g. 32-bit address
  // used in 64-bit).
  if (addr_op.address_size < word_size) {
    auto addr_type = llvm::Type::getIntNTy(
        *arch->context, static_cast<unsigned>(addr_op.address_size));

    addr = EmplaceUnaryOp(llvm::Instruction::Trunc, addr, addr_type);
    addr = EmplaceUnaryOp(llvm::Instruction::ZExt, addr, word_type);
  }
  op.expr = addr;
  op.type = Operand::kTypeAddressExpression;
  return op;
}

std::string Instruction::Serialize(void) const {
  std::stringstream ss;
  ss << "(";

  auto stream_arch = [&ss](ArchName an) {
    switch (an) {
      case kArchInvalid: ss << "INVALID"; break;
      case kArchAMD64:
      case kArchAMD64_AVX:
      case kArchAMD64_AVX512:
      case kArchAMD64_SLEIGH: ss << "AMD64"; break;
      case kArchX86:
      case kArchX86_AVX:
      case kArchX86_AVX512:
      case kArchX86_SLEIGH: ss << "X86"; break;
      case kArchThumb2LittleEndian: ss << "Thumb2"; break;
      case kArchAArch32LittleEndian: ss << "AArch32"; break;
      case kArchAArch64LittleEndian_SLEIGH:
      case kArchAArch64LittleEndian: ss << "AArch64"; break;
      case kArchSparc32_SLEIGH:
      case kArchSparc32: ss << "SPARC32"; break;
      case kArchSparc64: ss << "SPARC64"; break;
      case kArchPPC: ss << "PowerPC"; break;
      case kArchMIPS: ss << "MIPS"; break;
    }
  };

  auto maybe_stream_branch_taken_arch = [this, &ss, &stream_arch]() {
    if (branch_taken_arch_name && *branch_taken_arch_name != arch_name) {
      ss << ':';
      stream_arch(*branch_taken_arch_name);
    }
  };

  stream_arch(arch_name);

  if (sub_arch_name != arch_name) {
    switch (arch_name) {
      default: break;
      case kArchAMD64_AVX: ss << ":AVX"; break;
      case kArchAMD64_AVX512: ss << ":AVX512"; break;
      case kArchX86_AVX: ss << ":AVX"; break;
      case kArchX86_AVX512: ss << ":AVX512"; break;
      case kArchThumb2LittleEndian: ss << ":Thumb2"; break;
    }
  }

  ss << " " << std::hex << pc;

  if (IsValid()) {
    if (bytes.empty()) {
      ss << " (NO-BYTES)";

    } else {
      ss << " (BYTES";
      for (auto byte : bytes) {
        ss << " " << std::setw(2) << std::setfill('0') << std::hex
           << static_cast<unsigned>(static_cast<uint8_t>(byte));
      }
      ss << ")";
    }

  } else if (bytes.empty()) {
    ss << " (NO-BYTES)";

  } else {

    // if the instruction is invalid print the bytes
    // It will be helpful in mapping to the instruction in the absence of binary
    ss << " (BYTES";
    for (auto byte : bytes) {
      ss << " " << std::setw(2) << std::setfill('0') << std::hex
         << static_cast<unsigned>(static_cast<uint8_t>(byte));
    }
    ss << ")";
  }

  if (function.empty()) {
    ss << " !NO-FUNCTION!";
  } else {
    ss << " " << function;
  }

  if (segment_override) {
    ss << "(SEGMENT_OVERRIDE " << segment_override->name << ")";
  }

  for (const auto &op : operands) {
    ss << " " << op.Serialize();
  }

  if (is_atomic_read_modify_write) {
    ss << " IS_ATOMIC";
  }

  if (has_branch_taken_delay_slot || has_branch_not_taken_delay_slot) {
    ss << " (DELAY_SLOT";
    if (has_branch_taken_delay_slot) {
      ss << " (TAKEN " << std::hex << delayed_pc << std::dec << ")";
    }
    if (has_branch_not_taken_delay_slot) {
      ss << " (NOT_TAKEN " << std::hex << delayed_pc << std::dec << ")";
    }
    ss << ")";
  }

  if (in_delay_slot) {
    ss << " IN_DELAY_SLOT";
  }

  switch (category) {
    case Instruction::kCategoryDirectJump:
      ss << " (BRANCH " << std::hex << branch_taken_pc << std::dec;
      maybe_stream_branch_taken_arch();
      ss << ")";
      break;
    case Instruction::kCategoryDirectFunctionCall:
      ss << " (DIRECT_CALL (TAKEN " << std::hex << branch_taken_pc;
      maybe_stream_branch_taken_arch();
      ss << ")"
         << " (RETURN " << branch_not_taken_pc << std::dec << "))";
      break;
    case Instruction::kCategoryIndirectFunctionCall:
      ss << " (INDIRECT_CALL (TAKEN <unknown>";
      maybe_stream_branch_taken_arch();
      ss << ")"
         << " (RETURN " << std::hex << branch_not_taken_pc << std::dec << "))";
      break;
    case Instruction::kCategoryConditionalBranch:
      ss << " (COND_BRANCH (TAKEN " << std::hex << branch_taken_pc;
      maybe_stream_branch_taken_arch();
      ss << ")"
         << " (NOT_TAKEN " << branch_not_taken_pc << std::dec << "))";
      break;
    case kCategoryConditionalIndirectJump:
      ss << " (COND_BRANCH (TAKEN <unknown>";
      maybe_stream_branch_taken_arch();
      ss << ")"
         << " (NOT_TAKEN " << std::hex << branch_not_taken_pc << std::dec
         << "))";
      break;
    default: break;
  }

  ss << ")";
  return ss.str();
}

const InstructionLifter::LifterPtr &Instruction::GetLifter() const {
  return this->lifter;
}

void Instruction::SetLifter(InstructionLifter::LifterPtr lifter_) {
  lifter.swap(lifter_);
}

Instruction::DirectFlow::DirectFlow(uint64_t known_target_,
                                    DecodingContext static_context_)
    : known_target(known_target_),
      static_context(std::move(static_context_)) {}

Instruction::IndirectFlow::IndirectFlow(
    std::optional<DecodingContext> maybe_context_)
    : maybe_context(std::move(maybe_context_)) {}


Instruction::FallthroughFlow::FallthroughFlow(
    DecodingContext fallthrough_context_)
    : fallthrough_context(std::move(fallthrough_context_)) {}


Instruction::NormalInsn::NormalInsn(FallthroughFlow fallthrough_)
    : fallthrough(std::move(fallthrough_)) {}

Instruction::DirectJump::DirectJump(DirectFlow taken_flow_)
    : taken_flow(std::move(taken_flow_)) {}

Instruction::IndirectJump::IndirectJump(IndirectFlow taken_flow_)
    : taken_flow(std::move(taken_flow_)) {}

Instruction::ConditionalInstruction::ConditionalInstruction(
    AbnormalFlow taken_branch_, FallthroughFlow fall_through_)
    : taken_branch(std::move(taken_branch_)),
      fall_through(std::move(fall_through_)) {}

// TODO(Ian): When we bump remill to C++20 we can replace all of these comparisons with =default.
bool Instruction::DirectJump::operator==(const DirectJump &rhs) const {
  return this->taken_flow == rhs.taken_flow;
}

bool Instruction::DirectFlow::operator==(
    remill::Instruction::DirectFlow const &rhs) const {
  return this->known_target == rhs.known_target &&
         this->static_context == rhs.static_context;
}

bool Instruction::NormalInsn::operator==(
    remill::Instruction::NormalInsn const &rhs) const {
  return this->fallthrough == rhs.fallthrough;
}

bool Instruction::InvalidInsn::operator==(
    remill::Instruction::InvalidInsn const &invalid) const {
  return true;
}

bool Instruction::IndirectJump::operator==(
    remill::Instruction::IndirectJump const &rhs) const {
  return this->taken_flow == rhs.taken_flow;
}

bool Instruction::AsyncHyperCall::operator==(
    remill::Instruction::AsyncHyperCall const &rhs) const {
  return true;
}

bool Instruction::FunctionReturn::operator==(
    remill::Instruction::FunctionReturn const &rhs) const {
  return Instruction::IndirectJump::operator==(rhs);
}

bool Instruction::FallthroughFlow::operator==(
    remill::Instruction::FallthroughFlow const &rhs) const {
  return this->fallthrough_context == rhs.fallthrough_context;
}

bool Instruction::DirectFunctionCall::operator==(
    remill::Instruction::DirectFunctionCall const &rhs) const {
  return Instruction::DirectJump::operator==(rhs);
}

bool Instruction::ConditionalInstruction::operator==(
    remill::Instruction::ConditionalInstruction const &rhs) const {
  return this->fall_through == rhs.fall_through &&
         this->taken_branch == rhs.taken_branch;
}

bool Instruction::IndirectFlow::operator==(
    remill::Instruction::IndirectFlow const &rhs) const {
  return this->maybe_context == rhs.maybe_context;
}

bool Instruction::IndirectFunctionCall::operator==(
    remill::Instruction::IndirectFunctionCall const &rhs) const {
  return Instruction::IndirectJump::operator==(rhs);
}

bool Instruction::ErrorInsn::operator==(
    remill::Instruction::ErrorInsn const &) const {
  return true;
}


bool Instruction::NoOp::operator==(const NoOp &rhs) const {
  return this->fallthrough == rhs.fallthrough;
}

}  // namespace remill
