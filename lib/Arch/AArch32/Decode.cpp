/*
 * Copyright (c) 2020 Trail of Bits, Inc.
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

#include "Arch.h"
#include "remill/BC/ABI.h"

#include <glog/logging.h>

namespace remill {

namespace {

//Integer Data Processing (three register, register shift)
union IntDataProcessingRRRR {
  uint32_t flat;
  struct {
    uint32_t rm : 4;
    uint32_t _1 : 1;
    uint32_t type : 2;
    uint32_t _0 : 1;
    uint32_t rs : 4;
    uint32_t rd : 4;
    uint32_t rn : 4;
    uint32_t s : 1;
    uint32_t opc : 3;
    uint32_t _0000 : 4;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(IntDataProcessingRRRR) == 4, " ");

//Integer Data Processing (three register, immediate shift)
union IntDataProcessingRRRI {
  uint32_t flat;
  struct {
    uint32_t rm : 4;
    uint32_t _0 : 1;
    uint32_t type : 2;
    uint32_t imm5 : 5;
    uint32_t rd : 4;
    uint32_t rn : 4;
    uint32_t s : 1;
    uint32_t opc : 3;
    uint32_t _0000 : 4;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(IntDataProcessingRRRI) == 4, " ");

//Integer Data Processing (2 register and immediate, immediate shift)
union IntDataProcessingRRI {
  uint32_t flat;
  struct {
    uint32_t imm12 : 12;
    uint32_t rd : 4;
    uint32_t rn : 4;
    uint32_t s : 1;
    uint32_t opc : 3;
    uint32_t _0010 : 4;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(IntDataProcessingRRI) == 4, " ");

// Multiply and Accumulate
union MultiplyAndAccumulate {
  uint32_t flat;
  struct {
    uint32_t rn : 4;
    uint32_t _1001  : 4;
    uint32_t rm : 4;
    uint32_t rdlo : 4;
    uint32_t rdhi : 4;
    uint32_t s : 1;
    uint32_t opc : 3;
    uint32_t _0000 : 4;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(MultiplyAndAccumulate) == 4, " ");

// Halfword Multiply and Accumulate
union HMultiplyAndAccumulate {
  uint32_t flat;
  struct {
    uint32_t rn : 4;
    uint32_t _0_b4 : 1;
    uint32_t N  : 1;
    uint32_t M  : 1;
    uint32_t _1  : 1;
    uint32_t rm : 4;
    uint32_t ra : 4;
    uint32_t rd : 4;
    uint32_t _0_b20 : 1;
    uint32_t opc : 2;
    uint32_t _00010 : 5;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(HMultiplyAndAccumulate) == 4, " ");

// Load/Store Word, Unsigned Byte (immediate, literal)
union LoadStoreWUBIL {
  uint32_t flat;
  struct {
    uint32_t imm12 : 12;
    uint32_t rt : 4;
    uint32_t rn  : 4;
    uint32_t o1 : 1;
    uint32_t W : 1;
    uint32_t o2 : 1;
    uint32_t u : 1;
    uint32_t P : 1;
    uint32_t _010 : 3;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(LoadStoreWUBIL) == 4, " ");

// Integer Test and Compare (two register, immediate shift)
union IntTestCompRRI {
  uint32_t flat;
  struct {
    uint32_t rm : 4;
    uint32_t _0 : 1;
    uint32_t type : 2;
    uint32_t imm5 : 5;
    uint32_t _0000 : 4;
    uint32_t rn  : 4;
    uint32_t _1 : 1;
    uint32_t opc : 2;
    uint32_t _00010 : 5;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(IntTestCompRRI) == 4, " ");

// Integer Test and Compare (two register, register shift)
union IntTestCompRRR {
  uint32_t flat;
  struct {
    uint32_t rm : 4;
    uint32_t _1_b4 : 1;
    uint32_t type : 2;
    uint32_t _0 : 1;
    uint32_t rs : 4;
    uint32_t _0000 : 4;
    uint32_t rn  : 4;
    uint32_t _1_b20 : 1;
    uint32_t opc : 2;
    uint32_t _00010 : 5;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(IntTestCompRRR) == 4, " ");

// Integer Test and Compare (one register and immediate)
union IntTestCompRI {
  uint32_t flat;
  struct {
    uint32_t imm12 : 12;
    uint32_t _0000 : 4;
    uint32_t rn  : 4;
    uint32_t _1 : 1;
    uint32_t opc : 2;
    uint32_t _00110 : 5;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(IntTestCompRI) == 4, " ");

// Logical Arithmetic (three register, immediate shift)
union LogicalArithRRRI {
  uint32_t flat;
  struct {
    uint32_t rm  : 4;
    uint32_t _0 : 1;
    uint32_t type : 2;
    uint32_t imm5 : 5;
    uint32_t rd : 4;
    uint32_t rn  : 4;
    uint32_t s : 1;
    uint32_t opc : 2;
    uint32_t _00011 : 5;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(LogicalArithRRRI) == 4, " ");

// Logical Arithmetic (three register, register shift)
union LogicalArithRRRR {
  uint32_t flat;
  struct {
    uint32_t rm  : 4;
    uint32_t _1 : 1;
    uint32_t type : 2;
    uint32_t _0 : 1;
    uint32_t rs : 4;
    uint32_t rd : 4;
    uint32_t rn  : 4;
    uint32_t s : 1;
    uint32_t opc : 2;
    uint32_t _00011 : 5;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(LogicalArithRRRR) == 4, " ");

union LogicalArithmeticRRI {
  uint32_t flat;
    struct {
      uint32_t imm12 : 12;
      uint32_t rd : 4;
      uint32_t rn  : 4;
      uint32_t s : 1;
      uint32_t opc : 2;
      uint32_t _00111 : 5;
      uint32_t cond : 4;
    } __attribute__((packed));
  } __attribute__((packed));
static_assert(sizeof(LogicalArithmeticRRI) == 4, " ");

// Top-level encodings for A32
union TopLevelEncodings {
  uint32_t flat;
  struct {
    uint32_t _3_to_0 : 4;
    uint32_t op1 : 1;
    uint32_t _24_to_5 : 20;
    uint32_t op0 : 3;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(TopLevelEncodings) == 4, " ");

// Data-processing and miscellaneous instructions
union DataProcessingAndMisc {
  uint32_t flat;
  struct {
    uint32_t _3_to_0 : 4;
    uint32_t op4 : 1;
    uint32_t op3 : 2;
    uint32_t op2 : 1;
    uint32_t _19_to_8 : 12;
    uint32_t op1 : 5;
    uint32_t op0 : 1;
    uint32_t _00 : 2;
    uint32_t _not1111 : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(DataProcessingAndMisc) == 4, " ");

// Branch (Immediate)
union BranchI {
  uint32_t flat;
  struct {
    int32_t imm24 : 24;
    uint32_t H : 1;
    uint32_t _101 : 3;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(BranchI) == 4, " ");

// Miscellaneous
union Misc {
  uint32_t flat;
  struct {
    uint32_t Rm : 4;
    uint32_t op1 : 3;
    uint32_t _0_b7 : 1;
    uint32_t _11_to_8 : 4;
    uint32_t Rd : 4;
    uint32_t _19_to_16 : 4;
    uint32_t _0_b20 : 1;
    uint32_t op0 : 2;
    uint32_t _00010: 5;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(BranchI) == 4, " ");

static constexpr auto kPCRegNum = 15u;
static constexpr auto kLRRegNum = 14u;

static const char * const kIntRegName[] = {
    "R0",
    "R1",
    "R2",
    "R3",
    "R4",
    "R5",
    "R6",
    "R7",
    "R8",
    "R9",
    "R10",
    "R11",
    "R12",
    "R13",
    "R14",
    "R15"
};

typedef bool (TryDecode)(Instruction&, uint32_t);
typedef std::optional<uint32_t> (InstEval)(uint32_t, uint32_t);

static void AddIntRegOp(Instruction &inst, unsigned index, unsigned size,
                        Operand::Action action) {
  Operand::Register reg;
  reg.size = size;
  reg.name = kIntRegName[index];
  auto &op = inst.EmplaceOperand(reg);
  op.action = action;
}

static void AddIntRegOp(Instruction &inst, const char *reg_name, unsigned size,
                        Operand::Action action) {
  Operand::Register reg;
  reg.size = size;
  reg.name = reg_name;
  auto &op = inst.EmplaceOperand(reg);
  op.action = action;
}

static void AddExprOp(Instruction &inst, OperandExpression *op_expr,
                      uint64_t size = 32, Operand::Action action =
                          Operand::kActionRead) {
  inst.operands.emplace_back();
  auto &op = inst.operands.back();
  op.expr = op_expr;
  op.type = Operand::kTypeExpression;
  op.size = size;
  op.action = action;
}

static void AddImmOp(Instruction &inst, uint64_t value, unsigned size = 32,
                     bool is_signed = false) {
  Operand::Immediate imm;
  imm.val = value;
  imm.is_signed = is_signed;
  auto &op = inst.EmplaceOperand(imm);
  op.action = Operand::kActionRead;
  op.size = size;
}

static void AddAddrRegOp(Instruction &inst, const char *reg_name,
                         unsigned mem_size, Operand::Action mem_action,
                         unsigned disp, unsigned scale = 0) {
  Operand::Address addr;
  addr.address_size = 32;
  addr.base_reg.name = reg_name;
  addr.base_reg.size = 32;
  addr.scale = scale;
  addr.displacement = disp;
  auto &op = inst.EmplaceOperand(addr);
  op.size = mem_size;
  op.action = mem_action;
}

static void AddShiftOp(Instruction &inst,
                       Operand::ShiftRegister::Shift shift_op,
                       const char *reg_name, unsigned reg_size,
                       unsigned shift_size) {
  Operand::ShiftRegister shift_reg;
  shift_reg.reg.name = reg_name;
  shift_reg.reg.size = reg_size;
  shift_reg.shift_op = shift_op;
  shift_reg.shift_size = shift_size;
  auto &op = inst.EmplaceOperand(shift_reg);
  op.action = Operand::kActionRead;
}

static void AddShiftThenExtractOp(Instruction &inst,
                                  Operand::ShiftRegister::Shift shift_op,
                                  Operand::ShiftRegister::Extend extend_op,
                                  const char *reg_name, unsigned reg_size,
                                  unsigned shift_size, unsigned extract_size) {
  Operand::ShiftRegister shift_reg;
  shift_reg.reg.name = reg_name;
  shift_reg.reg.size = reg_size;
  shift_reg.shift_op = shift_op;
  shift_reg.shift_size = shift_size;
  shift_reg.extract_size = extract_size;
  shift_reg.extend_op = extend_op;
  shift_reg.shift_first = true;
  auto &op = inst.EmplaceOperand(shift_reg);
  op.action = Operand::kActionRead;

}

//static void AddExtractThenShiftOp(Instruction &inst,
//                                  Operand::ShiftRegister::Shift shift_op,
//                                  Operand::ShiftRegister::Extend extend_op,
//                                  const char *reg_name, unsigned reg_size,
//                                  unsigned shift_size, unsigned extract_size) {
//  Operand::ShiftRegister shift_reg;
//  shift_reg.reg.name = reg_name;
//  shift_reg.reg.size = reg_size;
//  shift_reg.shift_op = shift_op;
//  shift_reg.shift_size = shift_size;
//  shift_reg.extract_size = extract_size;
//  shift_reg.extend_op = extend_op;
//  shift_reg.shift_first = false;
//  auto &op = inst.EmplaceOperand(shift_reg);
//  op.action = Operand::kActionRead;
//}


// Note: Order is significant; extracted bits may be casted to this type.
enum Shift : uint32_t { kShiftLSL, kShiftLSR, kShiftASR, kShiftROR };

// Translate a shift encoding into an operand shift type used by the shift
// register class.
static Operand::ShiftRegister::Shift GetOperandShift(Shift s) {
  switch (s) {
    case kShiftLSL:
      return Operand::ShiftRegister::kShiftLeftWithZeroes;
    case kShiftLSR:
      return Operand::ShiftRegister::kShiftUnsignedRight;
    case kShiftASR:
      return Operand::ShiftRegister::kShiftSignedRight;
    case kShiftROR:
      return Operand::ShiftRegister::kShiftRightAround;
  }
  return Operand::ShiftRegister::kShiftInvalid;
}

// Do an extraction and zero extension on an expression
template<unsigned ext = llvm::Instruction::ZExt>
static OperandExpression * ExtractAndExtExpr(Instruction &inst, OperandExpression * op_expr,
                               unsigned int extract_size,
                               unsigned int extend_size) {
  auto extract_type = llvm::Type::getIntNTy(*(inst.arch->context),
                                            extract_size);
  auto extend_type = llvm::Type::getIntNTy(*(inst.arch->context),
                                           extend_size);

  // Extract bits
  op_expr = inst.EmplaceUnaryOp(llvm::Instruction::Trunc, op_expr,
                                extract_type);
  // ZExtend operand to extend_size
  if (extend_size > extract_size) {
    op_expr = inst.EmplaceUnaryOp(ext, op_expr, extend_type);
  }
  return op_expr;
}

// Note: This function adds either 1 or 2 operands in total
// an op and an optional additional carry_out op
// Used to handle semantics for:
// (imm32, carry) = A32ExpandImm_C(imm12, PSTATE.C);
// See an instruction in Data-processing register (immediate shift) for example
static void ExpandTo32AddImmAddCarry(Instruction &inst, uint32_t imm12,
                                     bool carry_out) {
  uint32_t unrotated_value = imm12 & (0b11111111u);
  uint32_t rotation_amount = ((imm12 >> 8) & (0b1111u)) * 2u;

  if (!rotation_amount) {
    AddImmOp(inst, unrotated_value);
  } else {
    AddImmOp(inst, __builtin_rotateright32(unrotated_value, rotation_amount));
  }

  if (carry_out) {
    if (!rotation_amount) {
      AddIntRegOp(inst, "C", 8u, Operand::kActionRead);
      inst.operands.back().expr = ExtractAndExtExpr(inst,
                                                     inst.operands.back().expr,
                                                     1u, 8u);
    } else {
      AddImmOp(inst,
               (unrotated_value >> ((rotation_amount + 31u) % 32u)) & 0b1u);
    }
  }
}

static OperandExpression * RORExpr(Instruction &inst,
                                   OperandExpression * op_expr,
                                   OperandExpression * shift_amount) {
  const auto word_type = inst.arch->AddressType();
  const auto _32 = llvm::ConstantInt::get(word_type, 32u, false);

  shift_amount = inst.EmplaceBinaryOp(llvm::Instruction::URem, shift_amount,
                                      inst.EmplaceConstant(_32));
  auto lhs_expr = inst.EmplaceBinaryOp(llvm::Instruction::LShr, op_expr,
                                       shift_amount);
  auto rhs_expr = inst.EmplaceBinaryOp(llvm::Instruction::Shl, op_expr,
                                       inst.EmplaceBinaryOp(llvm::Instruction::Sub,
                                       inst.EmplaceConstant(_32),
                                       shift_amount));
  op_expr = inst.EmplaceBinaryOp(llvm::Instruction::Or, lhs_expr, rhs_expr);
  return op_expr;
}

static void AddShiftRegCarryOperand(Instruction &inst, uint32_t reg_num,
                                    uint32_t shift_type,
                                    uint32_t shift_reg_num) {
  auto carry_expr = inst.EmplaceRegister(kIntRegName[reg_num]);

  // Create expression for the low 8 bits of the shift register
  auto shift_val_expr_c = inst.EmplaceRegister(kIntRegName[shift_reg_num]);
  shift_val_expr_c = ExtractAndExtExpr(inst, shift_val_expr_c, 8u, 32u);

  const auto word_type = inst.arch->AddressType();
  const auto _1 = llvm::ConstantInt::get(word_type, 1u, false);
  const auto _31 = llvm::ConstantInt::get(word_type, 31u, false);
  const auto _32 = llvm::ConstantInt::get(word_type, 32u, false);

  switch (static_cast<Shift>(shift_type)) {
    case Shift::kShiftASR:
      // shift_size - 1u
      shift_val_expr_c = inst.EmplaceBinaryOp(llvm::Instruction::Sub,
                                              shift_val_expr_c,
                                              inst.EmplaceConstant(_1));
      carry_expr = inst.EmplaceBinaryOp(llvm::Instruction::AShr, carry_expr,
                                        shift_val_expr_c);
      break;
    case Shift::kShiftLSL:
      // 32u - shift_size
      shift_val_expr_c = inst.EmplaceBinaryOp(llvm::Instruction::Sub,
                                              inst.EmplaceConstant(_32),
                                              shift_val_expr_c);
      carry_expr = inst.EmplaceBinaryOp(llvm::Instruction::LShr, carry_expr,
                                        shift_val_expr_c);
      break;
    case Shift::kShiftLSR:
      // shift_size - 1u
      shift_val_expr_c = inst.EmplaceBinaryOp(llvm::Instruction::Sub,
                                              shift_val_expr_c,
                                              inst.EmplaceConstant(_1));
      carry_expr = inst.EmplaceBinaryOp(llvm::Instruction::LShr, carry_expr,
                                        shift_val_expr_c);
      break;
    case Shift::kShiftROR:
      // (shift_size + 31u) % 32u
      shift_val_expr_c = inst.EmplaceBinaryOp(llvm::Instruction::Add,
                                              shift_val_expr_c,
                                              inst.EmplaceConstant(_31));
      shift_val_expr_c = inst.EmplaceBinaryOp(llvm::Instruction::URem,
                                              shift_val_expr_c,
                                              inst.EmplaceConstant(_32));
      carry_expr = inst.EmplaceBinaryOp(llvm::Instruction::LShr, carry_expr,
                                        shift_val_expr_c);
      break;
    default:
      LOG(FATAL) << "Invalid shift bits " << shift_type << " in "
                 << inst.Serialize();

  }

  // Extract the sign bit and extend back to I8
  carry_expr = ExtractAndExtExpr(inst, carry_expr, 1u, 8u);

  AddExprOp(inst, carry_expr);
}

// Note: this has no RRX shift operation
static void AddShiftRegRegOperand(Instruction &inst, uint32_t reg_num,
                                  uint32_t shift_type, uint32_t shift_reg_num,
                                  bool carry_out) {
  auto op_expr = inst.EmplaceRegister(kIntRegName[reg_num]);

  // Create expression for the low 8 bits of the shift register
  auto shift_val_expr = inst.EmplaceRegister(kIntRegName[shift_reg_num]);
  shift_val_expr = ExtractAndExtExpr(inst, shift_val_expr, 8u, 32u);

  // Create the shift and carry expressions operations
  switch (static_cast<Shift>(shift_type)) {
    case Shift::kShiftASR:
      op_expr = inst.EmplaceBinaryOp(llvm::Instruction::AShr, op_expr,
                                     shift_val_expr);
      break;
    case Shift::kShiftLSL:
      op_expr = inst.EmplaceBinaryOp(llvm::Instruction::Shl, op_expr,
                                     shift_val_expr);
      break;
    case Shift::kShiftLSR:
      op_expr = inst.EmplaceBinaryOp(llvm::Instruction::LShr, op_expr,
                                     shift_val_expr);
      break;
    case Shift::kShiftROR:
      op_expr = RORExpr(inst, op_expr, shift_val_expr);
      break;
    default:
      LOG(FATAL) << "Invalid shift bits " << shift_type << " in "
                 << inst.Serialize();
  }

  AddExprOp(inst, op_expr);

  if (carry_out) {
    AddShiftRegCarryOperand(inst, reg_num, shift_type, shift_reg_num);
  }
}


// PLEASE SEE AddShiftRegImmOperand!
// This function extracts the carry_out that from the semantics that
// AddShiftRegImmOperand handles
static void AddShiftImmCarryOperand(Instruction &inst,
                                 uint32_t reg_num, uint32_t shift_type,
                                 uint32_t shift_size, const char * carry_reg_name) {
  auto is_rrx = false;
  if (!shift_size && shift_type == Shift::kShiftROR) {
    shift_size = 1;
    is_rrx = true;
  }

  if (!shift_size) {
    AddIntRegOp(inst, carry_reg_name, 8u, Operand::kActionRead);
    inst.operands.back().expr = ExtractAndExtExpr(inst,
                                                   inst.operands.back().expr,
                                                   1u, 8u);
  } else {
    switch (static_cast<Shift>(shift_type)) {
      case Shift::kShiftASR:
        AddShiftThenExtractOp(inst, Operand::ShiftRegister::kShiftSignedRight,
                              Operand::ShiftRegister::kExtendUnsigned,
                              kIntRegName[reg_num], 32, shift_size - 1, 1);
        break;
      case Shift::kShiftLSL:
        AddShiftThenExtractOp(inst, Operand::ShiftRegister::kShiftUnsignedRight,
                              Operand::ShiftRegister::kExtendUnsigned,
                              kIntRegName[reg_num], 32, 32 - shift_size, 1);
        break;
      case Shift::kShiftLSR:
        AddShiftThenExtractOp(inst, Operand::ShiftRegister::kShiftUnsignedRight,
                              Operand::ShiftRegister::kExtendUnsigned,
                              kIntRegName[reg_num], 32, shift_size - 1, 1);
        break;
      case Shift::kShiftROR:
        if (is_rrx) {
          AddIntRegOp(inst, reg_num, 32u, Operand::kActionRead);
          inst.operands.back().expr = ExtractAndExtExpr(inst, inst.operands.back().expr, 1u, 32u);
        } else {
          AddShiftThenExtractOp(inst,
                                Operand::ShiftRegister::kShiftUnsignedRight,
                                Operand::ShiftRegister::kExtendUnsigned,
                                kIntRegName[reg_num], 32,
                                (shift_size + 31u) % 32u, 1);
        }
        break;
    }
  }
}

// Adds a shift operand and optionally carry out operand
// Used to handle semantics for:
// (shift_t, shift_n) = DecodeImmShift(type, imm5);
// (shifted, carry) = Shift_C(R[m], shift_t, shift_n, PSTATE.C);
// See an instruction in Integer Data Processing (three register, immediate shift) set for an example
static void AddShiftRegImmOperand(Instruction &inst, uint32_t reg_num,
                                  uint32_t shift_type, uint32_t shift_size,
                                  bool carry_out) {
  auto is_rrx = false;
  if (!shift_size && shift_type == Shift::kShiftROR) {
    shift_size = 1;
    is_rrx = true;
  } else if (shift_type == Shift::kShiftLSR || shift_type == Shift::kShiftASR) {
    if (!shift_size) {
      shift_size = 32;
    }
  }

  if (!shift_size) {
    AddIntRegOp(inst, reg_num, 32, Operand::kActionRead);
  } else {
    if (is_rrx) {
      AddShiftOp(inst, Operand::ShiftRegister::kShiftUnsignedRight,
                 kIntRegName[reg_num], 32, 1);
    } else {
      AddShiftOp(inst, GetOperandShift(static_cast<Shift>(shift_type)),
                 kIntRegName[reg_num], 32, shift_size);
    }
  }

  // To handle rrx we need to take two components shift each and OR the results
  // together. We create this functionality by creating a new shift operand,
  // removing it from the instruction operand list, and adding a binary op to
  // the register operand that ORs the expressions together.
  if (is_rrx) {
    AddShiftOp(inst, Operand::ShiftRegister::kShiftLeftWithZeroes, "C", 8, 31);
    auto rrx_op = inst.operands.back().expr;
    inst.operands.pop_back();
    inst.operands.back().expr = inst.EmplaceBinaryOp(llvm::Instruction::Or,
                                                     inst.operands.back().expr,
                                                     rrx_op);
  }
  if (carry_out) {
    AddShiftImmCarryOperand(inst, reg_num, shift_type, shift_size, "C");
  }
}

// Decode the condition field and fill in the instruction conditions accordingly
static bool DecodeCondition(Instruction &inst, uint32_t cond) {

  auto _8_type = llvm::Type::getInt8Ty(*inst.arch->context);
  const auto _1 = llvm::ConstantInt::get(_8_type, 1u, false);
  // Use ~0 -> 11111111 with XOR op for negation
  const auto negate = llvm::ConstantInt::get(_8_type, ~0u, false);
  bool negate_conditions = false;
  bool is_cond = true;

  OperandExpression * op_expr = nullptr;
  switch (cond) {
    case 0b0001:
      negate_conditions = true;
      [[clang::fallthrough]];
    case 0b0000: {
      op_expr = inst.EmplaceRegister("Z");
      break;
    }
    case 0b0011:
      negate_conditions = true;
      [[clang::fallthrough]];
    case 0b0010: {
      op_expr = inst.EmplaceRegister("C");
      break;
    }
    case 0b0101:
      negate_conditions = true;
      [[clang::fallthrough]];
    case 0b0100: {
      op_expr = inst.EmplaceRegister("N");
      break;
    }
    case 0b0111:
      negate_conditions = true;
      [[clang::fallthrough]];
    case 0b0110: {
      op_expr = inst.EmplaceRegister("V");
      break;
    }
    case 0b1001:
      negate_conditions = true;
      [[clang::fallthrough]];
    case 0b1000: {
      auto c_expr = inst.EmplaceRegister("C");
      auto z_expr = inst.EmplaceRegister("Z");
      z_expr = inst.EmplaceBinaryOp(llvm::Instruction::Xor, z_expr,
                                     inst.EmplaceConstant(negate));
      op_expr = inst.EmplaceBinaryOp(llvm::Instruction::And, z_expr, c_expr);
      break;
    }
    case 0b1011:
      negate_conditions = true;
      [[clang::fallthrough]];
    case 0b1010: {
      auto n_expr = inst.EmplaceRegister("N");
      auto v_expr = inst.EmplaceRegister("V");
      op_expr = inst.EmplaceBinaryOp(llvm::Instruction::Xor, n_expr, v_expr);
      op_expr = inst.EmplaceBinaryOp(llvm::Instruction::Xor, op_expr,
                                     inst.EmplaceConstant(negate));
      break;
    }
    case 0b1101:
      negate_conditions = true;
      [[clang::fallthrough]];
    case 0b1100: {
      auto n_expr = inst.EmplaceRegister("N");
      auto v_expr = inst.EmplaceRegister("V");
      op_expr = inst.EmplaceBinaryOp(llvm::Instruction::Xor, n_expr, v_expr);
      op_expr = inst.EmplaceBinaryOp(llvm::Instruction::Xor, op_expr,
                                  inst.EmplaceConstant(negate));
      auto z_expr = inst.EmplaceRegister("Z");
      z_expr = inst.EmplaceBinaryOp(llvm::Instruction::Xor, z_expr,
                                           inst.EmplaceConstant(negate));
      op_expr = inst.EmplaceBinaryOp(llvm::Instruction::And, z_expr, op_expr);
      break;
    }
    case 0b1111:
    case 0b1110:
      op_expr = inst.EmplaceConstant(_1);
      is_cond = false;
      break;
    default:
      LOG(FATAL) << "Invalid condition bits " << cond << " in " << inst.Serialize();
      break;
  }

  if (negate_conditions) {
    op_expr = inst.EmplaceBinaryOp(llvm::Instruction::Xor, op_expr,
                                   inst.EmplaceConstant(negate));
  }

  AddExprOp(inst, op_expr, 8u);
  AddExprOp(inst, inst.EmplaceVariable(kBranchTakenVariableName, _8_type), 8u,
            Operand::kActionWrite);

  return is_cond;
}

std::optional<uint64_t> EvalReg(const Instruction &inst, const Operand::Register &op) {
  if (op.name == kIntRegName[kPCRegNum] || op.name == "PC") {
    return inst.pc;
  } else if (op.name == "NEXT_PC") {
    return inst.next_pc;
  } else if (op.name.empty()) {
    return 0u;
  } else {
    return std::nullopt;
  }
}

std::optional<uint64_t> EvalShift(const Operand::ShiftRegister &op,
                                  std::optional<uint64_t> maybe_val) {
  if (!maybe_val || !op.shift_size) {
    return maybe_val;
  }

  if (op.reg.size != 32) {
    return std::nullopt;
  }

  auto val = static_cast<uint32_t>(*maybe_val);

  switch (op.shift_op) {
    case Operand::ShiftRegister::kShiftInvalid:
      return maybe_val;
    case Operand::ShiftRegister::kShiftLeftAround:
      return __builtin_rotateleft32(val, static_cast<uint32_t>(op.shift_size));
    case Operand::ShiftRegister::kShiftRightAround:
      return __builtin_rotateright32(val, static_cast<uint32_t>(op.shift_size));
    case Operand::ShiftRegister::kShiftLeftWithOnes:
      return (val << op.shift_size) | ~(~0u << op.shift_size);
    case Operand::ShiftRegister::kShiftLeftWithZeroes:
      return val << op.shift_size;
    case Operand::ShiftRegister::kShiftUnsignedRight:
      return val >> op.shift_size;
    case Operand::ShiftRegister::kShiftSignedRight:
       return static_cast<uint32_t>(static_cast<int32_t>(val) >> op.shift_size);
    default:
      return std::nullopt;
  }
}

std::optional<uint64_t> EvalExtract(const Operand::ShiftRegister &op,
                                    std::optional<uint64_t> maybe_val) {
  if (!maybe_val || !op.extract_size) {
    return maybe_val;
  }

  if (op.reg.size != 32) {
    return std::nullopt;
  }

  auto val = static_cast<uint32_t>(*maybe_val);

  switch (op.extend_op) {
    case Operand::ShiftRegister::kExtendInvalid:
      return maybe_val;
    case Operand::ShiftRegister::kExtendSigned:
    {
      val &= (1u << (op.extract_size)) - 1u;
      auto sign = val >> (op.extract_size - 1u);

      if (sign) {
        val |= ~0u << op.extract_size;
      }

      return val;
    }
    case Operand::ShiftRegister::kExtendUnsigned:
      return val & ((1u << (op.extract_size)) - 1u);
    default:
      return std::nullopt;
  }
}

std::optional<uint64_t> EvalOperand(const Instruction &inst, const Operand &op) {
  switch(op.type) {
    case Operand::kTypeInvalid:
      return std::nullopt;
    case Operand::kTypeImmediate:
      return op.imm.val;
    case Operand::kTypeRegister:
      return EvalReg(inst, op.reg);
    case Operand::kTypeAddress:
    {
      auto seg_val = EvalReg(inst, op.addr.segment_base_reg);
      auto base_val = EvalReg(inst, op.addr.base_reg);
      auto index_val = EvalReg(inst, op.addr.index_reg);

      if (!seg_val || !base_val || !index_val) {
        return std::nullopt;
      }

      return static_cast<uint64_t>(
          static_cast<int64_t>(*seg_val) + static_cast<int64_t>(*base_val) +
          (static_cast<int64_t>(*index_val) * op.addr.scale) +
          op.addr.displacement);

    }
    case Operand::kTypeShiftRegister:
      if (op.shift_reg.shift_first) {
        return EvalExtract(op.shift_reg, EvalShift(op.shift_reg, EvalReg(inst, op.shift_reg.reg)));
      } else {
        return EvalShift(op.shift_reg, EvalExtract(op.shift_reg, EvalReg(inst, op.shift_reg.reg)));
      }
    default:
      return std::nullopt;
  }
}

// Handles appropriate branching semantics for:
// if d == 15 then
//   if setflags then
//      ALUExceptionReturn(result);
//   else
//      ALUWritePC(result);
static bool EvalPCDest(Instruction &inst, const bool s, const unsigned int rd,
                       InstEval *evaluator, bool is_cond) {
  if (rd == kPCRegNum) {
    // Updates the flags (condition codes)
    if (s) {
      inst.category = Instruction::kCategoryError;
      return false;
    } else {
      auto src1 = EvalOperand(inst, inst.operands[1]);
      auto src2 = EvalOperand(inst, inst.operands[2]);

      if (!src1 || !src2) {
        inst.category = Instruction::kCategoryIndirectJump;
      } else {
        auto res = evaluator(*src1, *src2);
        if (!res) {
          if (is_cond) {
            inst.branch_not_taken_pc = inst.next_pc;
            inst.category = Instruction::kCategoryConditionalIndirectJump;
          } else {
            inst.category = Instruction::kCategoryIndirectJump;
          }
        } else if (is_cond) {
          inst.branch_taken_pc = static_cast<uint64_t>(*res);
          inst.branch_not_taken_pc = inst.next_pc;
          inst.category = Instruction::kCategoryConditionalBranch;
        } else {
          inst.branch_taken_pc = static_cast<uint64_t>(*res);
          inst.category = Instruction::kCategoryDirectJump;
        }
      }
    }
  } else {
    inst.category = Instruction::kCategoryNormal;
  }
  return true;
}

// High 3 bit opc
static InstEval * kIdpEvaluators[] = {
    [0b000] = +[](uint32_t src1, uint32_t src2) {
      return std::optional<uint32_t>(src1 & src2);
    },
    [0b001] = +[](uint32_t src1, uint32_t src2) {
      return std::optional<uint32_t>(src1 ^ src2);
    },
    [0b010] = +[](uint32_t src1, uint32_t src2) {
      return std::optional<uint32_t>(src1 - src2);
    },
    [0b011] = +[](uint32_t src1, uint32_t src2) {
      return std::optional<uint32_t>(src2 - src1);
    },
    [0b100] = +[](uint32_t src1, uint32_t src2) {
      return std::optional<uint32_t>(src2 + src1);
    },
    [0b101] = +[](uint32_t src1, uint32_t src2) {
      return std::optional<uint32_t>(std::nullopt);
    },
    [0b110] = +[](uint32_t src1, uint32_t src2) {
      return std::optional<uint32_t>(std::nullopt);
    },
    [0b111] = +[](uint32_t src1, uint32_t src2) {
      return std::optional<uint32_t>(std::nullopt);
    },
};

// High 3 bit opc and low bit s, opc:s
static const char * const kIdpNamesRRR[] = {
    [0b0000] = "ANDrr",
    [0b0001] = "ANDSrr",
    [0b0010] = "EORrr",
    [0b0011] = "EORSrr",
    [0b0100] = "SUBrr",
    [0b0101] = "SUBSrr",
    [0b0110] = "RSBrr",
    [0b0111] = "RSBSrr",
    [0b1000] = "ADDrr",
    [0b1001] = "ADDSrr",
    [0b1010] = "ADCrr",
    [0b1011] = "ADCSrr",
    [0b1100] = "SBCrr",
    [0b1101] = "SBCSrr",
    [0b1110] = "RSCrr",
    [0b1111] = "RSCSrr"
};

//000     AND, ANDS (register)
//001     EOR, EORS (register)
//010 0 != 1101 SUB, SUBS (register) — SUB
//010 0 1101  SUB, SUBS (SP minus register) — SUB
//010 1 != 1101 SUB, SUBS (register) — SUBS
//010 1 1101  SUB, SUBS (SP minus register) — SUBS
//011     RSB, RSBS (register)
//100 0 != 1101 ADD, ADDS (register) — ADD
//100 0 1101  ADD, ADDS (SP plus register) — ADD
//100 1 != 1101 ADD, ADDS (register) — ADDS
//100 1 1101  ADD, ADDS (SP plus register) — ADDS
//101     ADC, ADCS (register)
//110     SBC, SBCS (register)
//111     RSC, RSCS (register)
static bool TryDecodeIntegerDataProcessingRRRI(Instruction &inst, uint32_t bits) {
  const IntDataProcessingRRRI enc = {bits};

  inst.function = kIdpNamesRRR[ (enc.opc << 1u) | enc.s];
  auto is_cond = DecodeCondition(inst, enc.cond);
  AddIntRegOp(inst, enc.rd, 32, Operand::kActionWrite);
  AddIntRegOp(inst, enc.rn, 32, Operand::kActionRead);
  AddShiftRegImmOperand(inst, enc.rm, enc.type, enc.imm5, enc.s);
  return EvalPCDest(inst, enc.s, enc.rd, kIdpEvaluators[enc.opc], is_cond);
}

// Integer Data Processing (three register, register shift)
static bool TryDecodeIntegerDataProcessingRRRR(Instruction &inst, uint32_t bits) {
  const IntDataProcessingRRRR enc = { bits };

  if (enc.rn == kPCRegNum || enc.rd == kPCRegNum || enc.rs == kPCRegNum
      || enc.rm == kPCRegNum) {
    inst.category = Instruction::kCategoryError;
    return false;
  }

  inst.function = kIdpNamesRRR[(enc.opc << 1u) | enc.s];
  DecodeCondition(inst, enc.cond);

  AddIntRegOp(inst, enc.rd, 32, Operand::kActionWrite);
  AddIntRegOp(inst, enc.rn, 32, Operand::kActionRead);
  AddShiftRegRegOperand(inst, enc.rm, enc.type, enc.rs, enc.s);

  inst.category = Instruction::kCategoryNormal;
  return true;
}

//000           AND, ANDS (immediate)
//001           EOR, EORS (immediate)
//010 0 != 11x1 SUB, SUBS (immediate) — SUB
//010 0    1101 SUB, SUBS (SP minus immediate) — SUB
//010 0    1111 ADR — A2 (alias of subtract)
//010 1 != 1101 SUB, SUBS (immediate) — SUBS
//010 1    1101 SUB, SUBS (SP minus immediate) — SUBS
//011           RSB, RSBS (immediate)
//100 0 != 11x1 ADD, ADDS (immediate) — ADD
//100 0    1101 ADD, ADDS (SP plus immediate) — ADD
//100 0    1111 ADR — A1 (alias of add)
//100 1 != 1101 ADD, ADDS (immediate) — ADDS
//100 1    1101 ADD, ADDS (SP plus immediate) — ADDS
//101           ADC, ADCS (immediate)
//110           SBC, SBCS (immediate)
//111           RSC, RSCS (immediate)
static bool TryDecodeIntegerDataProcessingRRI(Instruction &inst, uint32_t bits) {
  const IntDataProcessingRRI enc = { bits };

  inst.function = kIdpNamesRRR[(enc.opc << 1u) | enc.s];
  auto is_cond = DecodeCondition(inst, enc.cond);
  AddIntRegOp(inst, enc.rd, 32, Operand::kActionWrite);

  // Raise the program counter to align to a multiple of 4 bytes
  if (enc.rn == kPCRegNum && (enc.opc == 0b100u || enc.opc == 0b010u)) {
    int64_t diff = static_cast<int32_t>(inst.pc & ~(3u)) - static_cast<int32_t>(inst.pc);
    AddAddrRegOp(inst, "PC", 32, Operand::kActionRead, diff);
  } else {
    AddIntRegOp(inst, enc.rn, 32, Operand::kActionRead);
  }

  ExpandTo32AddImmAddCarry(inst, enc.imm12, enc.s);

  return EvalPCDest(inst, enc.s, enc.rd, kIdpEvaluators[enc.opc], is_cond);
}

static const char * const kMulAccRRR[] = {
    [0b0000] = "MUL",
    [0b0001] = "MULS",
    [0b0010] = "MLA",
    [0b0011] = "MLAS",
    [0b0100] = "UMAAL",
    [0b0101] = nullptr,
    [0b0110] = "MLS",
    [0b0111] = nullptr,
    [0b1000] = "UMULL",
    [0b1001] = "UMULLS",
    [0b1010] = "UMLAL",
    [0b1011] = "UMLALS",
    [0b1100] = "SMULL",
    [0b1101] = "SMULLS",
    [0b1110] = "SMLAL",
    [0b1111] = "SMLALS"
};

//000   MUL, MULS
//001   MLA, MLAS
//010 0 UMAAL - writes to RdHi + RdLo, read RdHi
//010 1 UNALLOCATED
//011 0 MLS
//011 1 UNALLOCATED
//100   UMULL, UMULLS - writes to RdHi + RdLo
//101   UMLAL, UMLALS - writes to RdHi + RdLo, read RdHi
//110   SMULL, SMULLS - writes to RdHi + RdLo
//111   SMLAL, SMLALS - writes to RdHi + RdLo, read RdHi
static bool TryDecodeMultiplyAndAccumulate(Instruction &inst, uint32_t bits) {
  const MultiplyAndAccumulate enc = { bits };
  // MUL, MULS only: if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;
  // All other instructions: if d == 15 || n == 15 || m == 15 || a == 15 then UNPREDICTABLE;
  if (enc.rdhi == kPCRegNum || (enc.rdlo == kPCRegNum && !enc.opc)
      || enc.rn == kPCRegNum || enc.rm == kPCRegNum) {
    inst.category = Instruction::kCategoryError;
    return false;
  }

  auto instruction = kMulAccRRR[(enc.opc << 1u) | enc.s];
  if (!instruction) {
    return false;
  }
  inst.function = instruction;
  DecodeCondition(inst, enc.cond);

  AddIntRegOp(inst, enc.rdhi, 32, Operand::kActionWrite);

  // 2nd write reg only needed for instructions with an opc that begins with 1 and UMALL
  if (((enc.opc >> 2) & 0b1u) || enc.opc == 0b010u) {
    // if dHi == dLo then UNPREDICTABLE;
    if (enc.rdlo == enc.rdhi){
      inst.category = Instruction::kCategoryError;
      return false;
    }
    AddIntRegOp(inst, enc.rdlo, 32, Operand::kActionWrite);
  }

  // If opc is UMAAL, UMLAL, SMLAL read RdHi, add 0 immediate for UMULL, SMULL
  if (enc.opc == 0b111u || enc.opc == 0b101u || enc.opc == 0b010u) {
    AddIntRegOp(inst, enc.rdhi, 32, Operand::kActionRead);
  } else if ((enc.opc >> 2) & 0b1u) {
    AddImmOp(inst, 0);
  }
  AddIntRegOp(inst, enc.rn, 32, Operand::kActionRead);
  AddIntRegOp(inst, enc.rm, 32, Operand::kActionRead);

  // If instruction is not MUL, UMULL, SMULL add read to RdLo otherwise add an immediate
  if (enc.opc != 0b000u && enc.opc != 0b100u && enc.opc != 0b110u) {
    AddIntRegOp(inst, enc.rdlo, 32, Operand::kActionRead);
  } else {
    AddImmOp(inst, 0);
  }

  inst.category = Instruction::kCategoryNormal;

  return true;
}

static const char * const kHMulAccRRR[] = {
    [0b0000] = "SMLABB", // (M == 0 && N == 0)
    [0b0010] = "SMLABT", // (M == 1 && N == 0)
    [0b0001] = "SMLATB", // (M == 0 && N == 1)
    [0b0011] = "SMLATT", // (M == 1 && N == 1)
    [0b0100] = "SMLAWB",
    [0b0101] = "SMULWB",
    [0b0110] = "SMLAWT",
    [0b0111] = "SMULWT",
    [0b1000] = "SMLALBB", // (M == 0 && N == 0)
    [0b1010] = "SMLALBT", // (M == 1 && N == 0)
    [0b1001] = "SMLALTB", // (M == 0 && N == 1)
    [0b1011] = "SMLALTT", // (M == 1 && N == 1)
    [0b1100] = "SMULBB", // (M == 0 && N == 0)
    [0b1110] = "SMULBT", // (M == 1 && N == 0)
    [0b1101] = "SMULTB", // (M == 0 && N == 1)
    [0b1111] = "SMULTT", // (M == 1 && N == 1)
};

// opc M N
// 00      SMLABB, SMLABT, SMLATB, SMLATT — writes to Rd, read Ra, Rm, Rn
// 01  0 0 SMLAWB, SMLAWT — SMLAWB — writes to Rd, read Ra, Rm, Rn
// 01  0 1 SMULWB, SMULWT — SMULWB — writes to Rd, read Rm, Rn
// 01  1 0 SMLAWB, SMLAWT — SMLAWT — writes to Rd, read Ra, Rm, Rn
// 01  1 1 SMULWB, SMULWT — SMULWT — writes to Rd, read Rm, Rn
// 10      SMLALBB, SMLALBT, SMLALTB, SMLALTT — writes to Rd, Ra, read Rd, Ra, Rm, Rn
// 11      SMULBB, SMULBT, SMULTB, SMULTT — writes to Rd, read Rm, Rn
// Halfword Multiply and Accumulate
// - under Data-processing and miscellaneous instructions
static bool TryHalfwordDecodeMultiplyAndAccumulate(Instruction &inst,
                                                   uint32_t bits) {

  const HMultiplyAndAccumulate enc = { bits };
  bool add_ra = enc.opc == 0b10u || (enc.opc == 0b1u && !enc.N) || !enc.opc;
  // if d == 15 || n == 15 || m == 15 || a == 15 then UNPREDICTABLE;
  // if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;
  // if dHi == dLo then UNPREDICTABLE;
  if (enc.rd == kPCRegNum || enc.rn == kPCRegNum || enc.rm == kPCRegNum
      || ((enc.ra == kPCRegNum) && add_ra)
      || ((enc.opc == 0b10u) && (enc.rd == enc.ra))) {
    inst.category = Instruction::kCategoryError;
  }

  inst.function = kHMulAccRRR[(enc.opc << 2u) | (enc.M << 1u) | enc.N];
  DecodeCondition(inst, enc.cond);

  AddIntRegOp(inst, enc.rd, 32, Operand::kActionWrite);

  // SMLALBB, SMLALBT, SMLALTB, SMLALTT add write ra and read rd
  if (enc.opc == 0b10u) {
    AddIntRegOp(inst, enc.ra, 32, Operand::kActionWrite);
    AddIntRegOp(inst, enc.rd, 32, Operand::kActionRead);
  }

  const auto word_type = inst.arch->AddressType();
  const auto _16 = llvm::ConstantInt::get(word_type, 16u, false);

  // Rn
  AddIntRegOp(inst, enc.rn, 32, Operand::kActionRead);
  if (enc.opc != 0b1u) {
    if (enc.N) {
      inst.operands.back().expr = inst.EmplaceBinaryOp(
          llvm::Instruction::AShr, inst.operands.back().expr,
          inst.EmplaceConstant(_16));
    } else {
      inst.operands.back().expr = ExtractAndExtExpr<llvm::Instruction::SExt>(
          inst, inst.operands.back().expr, 16u, 32u);
    }
  }

  // Rm
  AddIntRegOp(inst, enc.rm, 32, Operand::kActionRead);
  if (enc.M) {
    inst.operands.back().expr = inst.EmplaceBinaryOp(llvm::Instruction::AShr,
                                                     inst.operands.back().expr,
                                                     inst.EmplaceConstant(_16));
  } else {
    inst.operands.back().expr = ExtractAndExtExpr<llvm::Instruction::SExt>(
        inst, inst.operands.back().expr, 16u, 32u);
  }

  // Ra
  if (add_ra) {
    AddIntRegOp(inst, enc.ra, 32, Operand::kActionRead);
  } else if (enc.opc != 0b11u) {
    AddImmOp(inst, 0);
  }

  inst.category = Instruction::kCategoryNormal;
  return true;

}

static const char * const kLoadSWUBIL[] = {
    [0b0000] = "STRp",
    [0b0001] = "LDRp",
    [0b0010] = "STRBp",
    [0b0011] = "LDRBp",
    [0b0100] = "STRT",
    [0b0101] = "LDRT",
    [0b0110] = "STRBT",
    [0b0111] = "LDRBT",
    [0b1000] = "STR",
    [0b1001] = "LDR",
    [0b1010] = "STRB",
    [0b1011] = "LDRB",
    [0b1100] = "STRp",
    [0b1101] = "LDRp",
    [0b1110] = "STRBp",
    [0b1111] = "LDRBp",
};


// P:W o2 o1    Rn
//!= 01 0 1    1111 LDR (literal)
//!= 01 1 1    1111 LDRB (literal)
//   00 0 0         STR (immediate) — post-indexed
//   00 0 1 != 1111 LDR (immediate) — post-indexed
//   00 1 0         STRB (immediate) — post-indexed
//   00 1 1 != 1111 LDRB (immediate) — post-indexed
//   01 0 0         STRT
//   01 0 1         LDRT
//   01 1 0         STRBT
//   01 1 1         LDRBT
//   10 0 0         STR (immediate) — offset
//   10 0 1 != 1111 LDR (immediate) — offset
//   10 1 0         STRB (immediate) — offset
//   10 1 1 != 1111 LDRB (immediate) — offset
//   11 0 0         STR (immediate) — pre-indexed
//   11 0 1 != 1111 LDR (immediate) — pre-indexed
//   11 1 0         STRB (immediate) — pre-indexed
//   11 1 1 != 1111 LDRB (immediate) — pre-indexed
// LDR{<c>}{<q>} <Rt>, [<Rn> {, #{+/-}<imm>}]
// LDR{<c>}{<q>} <Rt>, [<Rn>], #{+/-}<imm>
// LDR{<c>}{<q>} <Rt>, [<Rn>, #{+/-}<imm>]!
template<Operand::Action kMemAction, Operand::Action kRegAction, unsigned kMemSize, bool kAlignPC = false>
static bool TryDecodeLoadStoreWordUBIL (Instruction &inst, uint32_t bits) {
  const LoadStoreWUBIL enc = { bits };

  bool write_back = (!enc.P || enc.W);
  if (write_back && (enc.rn == kPCRegNum || enc.rn == enc.rt)) {
    inst.category = Instruction::kCategoryError;
    return false;
  }

  auto instruction = kLoadSWUBIL[enc.P << 3u | enc.W << 2u | enc.o2 << 1u | enc.o1];

  inst.function = instruction;
  auto is_cond = DecodeCondition(inst, enc.cond);

  // LDR & LDRB (literal) are pc relative. Need to align the PC to the next nearest 4 bytes
  int64_t pc_adjust = 0;
  if (kAlignPC && enc.rn == kPCRegNum) {
    pc_adjust  = static_cast<int32_t>(inst.pc & ~(3u)) - static_cast<int32_t>(inst.pc);
  }
  auto disp = static_cast<int64_t>(enc.imm12);

  // Subtract
  if (!enc.u) {
    disp = -disp;
  }

  // Not Indexing
  if (!enc.P) {
    AddAddrRegOp(inst, kIntRegName[enc.rn], kMemSize, kMemAction, pc_adjust);
  } else {
    AddAddrRegOp(inst, kIntRegName[enc.rn], kMemSize, kMemAction, disp + pc_adjust);
  }

  AddIntRegOp(inst, enc.rt, 32, kRegAction);

  // Pre or Post Indexing
  if (write_back) {
    AddIntRegOp(inst, enc.rn, 32, Operand::kActionWrite);
    AddAddrRegOp(inst, kIntRegName[enc.rn], 32, Operand::kActionRead, disp + pc_adjust);
  }

  if (enc.rt == kPCRegNum) {
    if (is_cond) {
      inst.branch_not_taken_pc = inst.next_pc;
      inst.category = Instruction::kCategoryConditionalIndirectJump;
    } else {
      inst.category = Instruction::kCategoryIndirectJump;
    }
  } else {
    inst.category = Instruction::kCategoryNormal;
  }
  return true;
}

// Can package semantics for MOV with ORR and MVN with BIC since src1 will be
// 0 and 1 for MOV and MVN respectively, mirroring the semantics in LOGICAL.cpp
static InstEval * kLogArithEvaluators[] = {
    [0b0] = +[](uint32_t src1, uint32_t src2) {
      return std::optional<uint32_t>(src1 | src2);
    },
    [0b1] = +[](uint32_t src1, uint32_t src2) {
      return std::optional<uint32_t>(src1 & ~src2);
    },
};

//00  ORR, ORRS (register) -- rd, rn, & rm
//01  MOV, MOVS (register) -- rd, & rm only
//10  BIC, BICS (register) -- rd, rn, & rm
//11  MVN, MVNS (register) -- rd, & rm only
static const char * const kLogicalArithmeticRRRI[] = {
    [0b000] = "ORRrr",
    [0b001] = "ORRSrr",
    [0b010] = "MOVrr",
    [0b011] = "MOVSrr",
    [0b100] = "BICrr",
    [0b101] = "BICSrr",
    [0b110] = "MVNrr",
    [0b111] = "MVNSrr",
};

// Logical Arithmetic (three register, immediate shift)
static bool TryLogicalArithmeticRRRI(Instruction &inst, uint32_t bits) {
  const LogicalArithRRRI enc = { bits };

  auto instruction = kLogicalArithmeticRRRI[enc.opc << 1u | enc.s];

  inst.function = instruction;
  auto is_cond = DecodeCondition(inst, enc.cond);

  AddIntRegOp(inst, enc.rd, 32, Operand::kActionWrite);

  // enc.opc == x0
  if (!(enc.opc & 0b1u)) {
    AddIntRegOp(inst, enc.rn, 32, Operand::kActionRead);
  // enc.opc == 01
  } else if (!(enc.opc & 0b10u)) {
    AddImmOp(inst, 0);
  // enc.opc == 11
  } else {
    AddImmOp(inst, ~0u);
  }

  AddShiftRegImmOperand(inst, enc.rm, enc.type, enc.imm5, enc.s);
  return EvalPCDest(inst, enc.s, enc.rd, kLogArithEvaluators[enc.opc >> 1u], is_cond);
}

// Logical Arithmetic (three register, register shift)
static bool TryLogicalArithmeticRRRR(Instruction &inst, uint32_t bits) {
  const LogicalArithRRRR enc = { bits };

  if (enc.rn == kPCRegNum || enc.rd == kPCRegNum || enc.rs == kPCRegNum
      || enc.rm == kPCRegNum) {
    inst.category = Instruction::kCategoryError;
    return false;
  }

  inst.function = kLogicalArithmeticRRRI[enc.opc << 1u | enc.s];
  DecodeCondition(inst, enc.cond);


  AddIntRegOp(inst, enc.rd, 32, Operand::kActionWrite);
  // enc.opc == x0
  if (!(enc.opc & 0b1u)) {
    AddIntRegOp(inst, enc.rn, 32, Operand::kActionRead);
  // enc.opc == 01
  } else if (!(enc.opc & 0b10u)) {
    AddImmOp(inst, 0);
  // enc.opc == 11
  } else {
    AddImmOp(inst, ~0u);
  }
  AddShiftRegRegOperand(inst, enc.rm, enc.type, enc.rs, enc.s);
  inst.category = Instruction::kCategoryNormal;
  return true;
}

// Logical Arithmetic (two register and immediate)
static bool TryLogicalArithmeticRRI(Instruction &inst, uint32_t bits) {
  const LogicalArithmeticRRI enc = { bits };

  inst.function = kLogicalArithmeticRRRI[enc.opc << 1u | enc.s];
  auto is_cond = DecodeCondition(inst, enc.cond);

  AddIntRegOp(inst, enc.rd, 32, Operand::kActionWrite);
  // enc.opc == x0
  if (!(enc.opc & 0b1u)) {
    AddIntRegOp(inst, enc.rn, 32, Operand::kActionRead);
  // enc.opc == 01
  } else if (!(enc.opc & 0b10u)) {
    AddImmOp(inst, 0u);
  // enc.opc == 11
  } else {
    AddImmOp(inst, ~0u);
  }

  ExpandTo32AddImmAddCarry(inst, enc.imm12, enc.s);
  return EvalPCDest(inst, enc.s, enc.rd, kLogArithEvaluators[enc.opc >> 1u], is_cond);
}

//00  TST (register)
//01  TEQ (register)
//10  CMP (register)
//11  CMN (register)
static const char * const kIntegerTestAndCompareR[] = {
    [0b00] = "TSTr",
    [0b01] = "TEQr",
    [0b10] = "CMPr",
    [0b11] = "CMNr",
};

// Integer Test and Compare (two register, immediate shift)
static bool TryIntegerTestAndCompareRRI(Instruction &inst, uint32_t bits) {
  const IntTestCompRRI enc = { bits };

  auto instruction = kIntegerTestAndCompareR[enc.opc];

  inst.function = instruction;
  DecodeCondition(inst, enc.cond);

  AddIntRegOp(inst, enc.rn, 32, Operand::kActionRead);
  AddShiftRegImmOperand(inst, enc.rm, enc.type, enc.imm5, 1u);

  inst.category = Instruction::kCategoryNormal;
  return true;
}

// Integer Test and Compare (two register, register shift)
static bool TryIntegerTestAndCompareRRR(Instruction &inst, uint32_t bits) {
  const IntTestCompRRR enc = { bits };

  if (enc.rn == kPCRegNum || enc.rs == kPCRegNum || enc.rm == kPCRegNum) {
    inst.category = Instruction::kCategoryError;
    return false;
  }

  inst.function = kIntegerTestAndCompareR[enc.opc];
  DecodeCondition(inst, enc.cond);

  AddIntRegOp(inst, enc.rn, 32, Operand::kActionRead);
  AddShiftRegRegOperand(inst, enc.rm, enc.type, enc.rs, 1u);

  inst.category = Instruction::kCategoryNormal;
  return true;
}

// Integer Test and Compare (one register and immediate)
static bool TryIntegerTestAndCompareRI(Instruction &inst, uint32_t bits) {
  const IntTestCompRI enc = { bits };

  auto instruction = kIntegerTestAndCompareR[enc.opc];

  inst.function = instruction;
  DecodeCondition(inst, enc.cond);

  AddIntRegOp(inst, enc.rn, 32, Operand::kActionRead);
  ExpandTo32AddImmAddCarry(inst, enc.imm12, 1u);

  inst.category = Instruction::kCategoryNormal;
  return true;

}

// cond  H
//!= 1111 0 B
//!= 1111 1 BL, BLX (immediate) — A1
//1111    BL, BLX (immediate) — A2
// Branch (immediate)
static bool TryBranchImm(Instruction &inst, uint32_t bits) {
  const BranchI enc = { bits };
  auto is_cond = DecodeCondition(inst, enc.cond);

  auto is_func = false;
  // PC used by the branch instruction is actually the address of the next instruction
  auto target_pc = static_cast<uint32_t>(inst.pc + 8 + static_cast<uint32_t>(enc.imm24 << 2));
  if (enc.cond != 0b1111) {
    if (!enc.H) {
      target_pc = target_pc & ~0b11u;
      inst.function = "B";
    } else {
      target_pc = target_pc & ~0b11u;
      inst.function = "BL";
      is_func = true;
    }
  } else {
    inst.function = "BLX";
    target_pc = target_pc & ~0b11u;
    target_pc = target_pc | (enc.H << 1);
    is_func = true;
  }
  if (is_cond) {
    inst.function += "COND";
  }
  auto offset = static_cast<uint32_t>(target_pc - inst.pc);

  AddAddrRegOp(inst, "PC", 32u, Operand::kActionRead, offset);

  inst.branch_taken_pc = target_pc;
  inst.branch_not_taken_pc = inst.pc + 4;
  if (is_cond && is_func) {
    inst.category = Instruction::kCategoryConditionalDirectFunctionCall;
    AddAddrRegOp(inst, "NEXT_PC", 32u, Operand::kActionRead, 0);
  } else if (is_cond) {
    inst.category = Instruction::kCategoryConditionalBranch;
    AddAddrRegOp(inst, "NEXT_PC", 32u, Operand::kActionRead, 0);
  } else if (is_func) {
    inst.category = Instruction::kCategoryDirectFunctionCall;
    AddAddrRegOp(inst, "NEXT_PC", 32u, Operand::kActionRead, 0);
  } else {
    inst.category = Instruction::kCategoryDirectJump;
  }

  Operand::Register reg;
  reg.size = 32u;
  reg.name = remill::kNextPCVariableName;
  auto &next_pc = inst.EmplaceOperand(reg);
  next_pc.action = Operand::kActionWrite;

  if (is_func) {
    Operand::Register reg;
    reg.size = 32u;
    reg.name = remill::kReturnPCVariableName;
    auto &next_pc = inst.EmplaceOperand(reg);
    next_pc.action = Operand::kActionWrite;
  }

  return true;
}

static const char * const kBX[] = {
    [0b01] = "BX",
    [0b10] = "BXJ", // unsupported
    [0b11] = "BLX",
};

static bool TryDecodeBX(Instruction &inst, uint32_t bits) {
  const Misc enc = { bits };

  if (enc.op1 == 0b10) { // BJX unsupported
    LOG(ERROR) << "BJX unsupported";
    return false;
  } else if (enc.op1 == 0b11 && enc.Rm == kPCRegNum) {
    // if m == 15 then UNPREDICTABLE;
    return false;
  }

  auto is_cond = DecodeCondition(inst, enc.cond);
  inst.function = kBX[enc.op1];
  if (is_cond) {
    inst.function += "COND";
  }

  AddAddrRegOp(inst, kIntRegName[enc.Rm], 32u, Operand::kActionRead, 0);
  if (enc.op1 == 0b01) {
    if (is_cond && (enc.Rm == kLRRegNum)) {
      inst.category = Instruction::kCategoryConditionalFunctionReturn;
      AddAddrRegOp(inst, "NEXT_PC", 32u, Operand::kActionRead, 0);
    } else if (enc.Rm == kLRRegNum) {
      inst.category = Instruction::kCategoryFunctionReturn;
    } else if (is_cond) {
      inst.category = Instruction::kCategoryConditionalIndirectJump;
      AddAddrRegOp(inst, "NEXT_PC", 32u, Operand::kActionRead, 0);
    } else if (enc.op1 == 0b01) {
      inst.category = Instruction::kCategoryIndirectJump;
    }
  } else if (is_cond) {
    inst.category = Instruction::kCategoryConditionalDirectFunctionCall;
    AddAddrRegOp(inst, "NEXT_PC", 32u, Operand::kActionRead, 0);
  } else {
    inst.category = Instruction::kCategoryDirectFunctionCall;
  }

  Operand::Register reg;
  reg.size = 32u;
  reg.name = remill::kNextPCVariableName;
  auto &next_pc = inst.EmplaceOperand(reg);
  next_pc.action = Operand::kActionWrite;

  if (enc.op1 == 0b11) {
    Operand::Register reg;
    reg.size = 32u;
    reg.name = remill::kReturnPCVariableName;
    auto &next_pc = inst.EmplaceOperand(reg);
    next_pc.action = Operand::kActionWrite;
  }

  return true;
}

static bool TryDecodeCLZ(Instruction &inst, uint32_t bits) {
  const Misc enc = { bits };
  if (enc.Rd == kPCRegNum || enc.Rm == kPCRegNum) {
    // if d == 15 || m == 15 then UNPREDICTABLE;
    return false;
  }
  DecodeCondition(inst, enc.cond);

  AddIntRegOp(inst, enc.Rd, 32u, Operand::kActionWrite);
  AddIntRegOp(inst, enc.Rm, 32u, Operand::kActionRead);

  inst.function = "CLZ";
  inst.category = Instruction::kCategoryNormal;
  return true;
}


//00  001 UNALLOCATED
//00  010 UNALLOCATED
//00  011 UNALLOCATED
//00  110 UNALLOCATED
//01  001 BX
//01  010 BXJ
//01  011 BLX (register)
//01  110 UNALLOCATED
//10  001 UNALLOCATED
//10  010 UNALLOCATED
//10  011 UNALLOCATED
//10  110 UNALLOCATED
//11  001 CLZ
//11  010 UNALLOCATED
//11  011 UNALLOCATED
//11  110 ERET
//    111 Exception Generation
//    000 Move special register (register)
//    100 Cyclic Redundancy Check
//    101 Integer Saturating Arithmetic
static TryDecode * TryMiscellaneous(uint32_t bits) {
  const Misc enc = { bits };
  // op0 | op1
  switch (enc.op0 << 3 | enc.op1) {
    case 0b01001:
    case 0b01010:
    case 0b01011:
      return TryDecodeBX;
    case 0b11001:
      return TryDecodeCLZ;
    case 0b11110:  // TODO(Sonya): ERET
      return nullptr;
  }
  // TODO(Sonya)
  switch (enc.op1) {
    case 0b111: // Exception Generation
    case 0b000: // Move special register (register)
    case 0b100: // Cyclic Redundancy Check
    case 0b101: // Integer Saturating Arithmetic
    default: return nullptr;
  }
}

// Corresponds to Data-processing register (immediate shift)
// op0<24 to 23> | op1 <20>
static TryDecode * kDataProcessingRI[] = {
    [0b000] = TryDecodeIntegerDataProcessingRRRI,
    [0b001] = TryDecodeIntegerDataProcessingRRRI,
    [0b010] = TryDecodeIntegerDataProcessingRRRI,
    [0b011] = TryDecodeIntegerDataProcessingRRRI,
    [0b100] = nullptr, // op0:op1 != 100
    [0b101] = TryIntegerTestAndCompareRRI,
    [0b110] = TryLogicalArithmeticRRRI,
    [0b111] = TryLogicalArithmeticRRRI,
};

// Corresponds to Data-processing register (register shift)
// op0<24 to 23> | op1 <20>
static TryDecode * kDataProcessingRR[] = {
    [0b000] = TryDecodeIntegerDataProcessingRRRR,
    [0b001] = TryDecodeIntegerDataProcessingRRRR,
    [0b010] = TryDecodeIntegerDataProcessingRRRR,
    [0b011] = TryDecodeIntegerDataProcessingRRRR,
    [0b100] = nullptr, // op0:op1 != 100
    [0b101] = TryIntegerTestAndCompareRRR,
    [0b110] = TryLogicalArithmeticRRRR,
    [0b111] = TryLogicalArithmeticRRRR,
};

// Corresponds to Data-processing immediate
// op0<24 to 23> | op1 <21 to 20>
static TryDecode * kDataProcessingI[] = {
    [0b0000] = TryDecodeIntegerDataProcessingRRI,
    [0b0001] = TryDecodeIntegerDataProcessingRRI,
    [0b0010] = TryDecodeIntegerDataProcessingRRI,
    [0b0011] = TryDecodeIntegerDataProcessingRRI,
    [0b0100] = TryDecodeIntegerDataProcessingRRI,
    [0b0101] = TryDecodeIntegerDataProcessingRRI,
    [0b0110] = TryDecodeIntegerDataProcessingRRI,
    [0b0111] = TryDecodeIntegerDataProcessingRRI,
    [0b1000] = nullptr, // TODO(Sonya): Move Halfword (immediate)
    [0b1001] = TryIntegerTestAndCompareRI,
    [0b1010] = nullptr, // TODO(Sonya): Move Special Register and Hints (immediate)
    [0b1011] = TryIntegerTestAndCompareRI,
    [0b1100] = TryLogicalArithmeticRRI,
    [0b1101] = TryLogicalArithmeticRRI,
    [0b1110] = TryLogicalArithmeticRRI,
    [0b1111] = TryLogicalArithmeticRRI,
};

// Corresponds to: Load/Store Word, Unsigned Byte (immediate, literal)
// o2<22> | o1<21>
static TryDecode * kLoadStoreWordUBIL[] = {
    [0b00] = TryDecodeLoadStoreWordUBIL<Operand::kActionWrite, Operand::kActionRead, 32u>,
    [0b01] = TryDecodeLoadStoreWordUBIL<Operand::kActionRead, Operand::kActionWrite, 32u, true>,
    [0b10] = TryDecodeLoadStoreWordUBIL<Operand::kActionWrite, Operand::kActionRead, 8u>,
    [0b11] = TryDecodeLoadStoreWordUBIL<Operand::kActionRead, Operand::kActionWrite, 8u, true>,
};

// Corresponds to: Data-processing and miscellaneous instructions
//op0   op1    op2 op3  op4
// 0            1 != 00  1 Extra load/store
// 0     0xxxx  1    00  1 Multiply and Accumulate
// 0     1xxxx  1    00  1 Synchronization primitives and Load-Acquire/Store-Release
// 0     10xx0  0          Miscellaneous
// 0     10xx0  1        0 Halfword Multiply and Accumulate
// 0  != 10xx0           0 Data-processing register (immediate shift)
// 0  != 10xx0  0        1 Data-processing register (register shift)
// 1                       Data-processing immediate
static TryDecode * TryDataProcessingAndMisc(uint32_t bits) {
  const DataProcessingAndMisc enc = { bits };
  // op0 == 0
  if (!enc.op0) {
    // op2 == 1, op4 == 1
    if (enc.op2 && enc.op4) {
      // TODO(Sonya): Extra load/store -- op3 != 00
      if (!enc.op3) {
        return nullptr;
      // op3 == 00
      } else {
        // Multiply and Accumulate -- op1 == 0xxxx
        if (!(enc.op1 >> 4)) {
          return TryDecodeMultiplyAndAccumulate;
        // TODO(Sonya): Synchronization primitives and Load-Acquire/Store-Release -- op1 == 1xxxx
        } else {
          return nullptr;
        }
      }
    // op1 == 10xx0
    } else if (((enc.op1 >> 3) == 0b10u) && !(enc.op1 & 0b00001u)) {
      // Miscellaneous
      if (!enc.op2) {
        return TryMiscellaneous(bits);
      // Halfword Multiply and Accumulate
      } else {
        return TryHalfwordDecodeMultiplyAndAccumulate;
      }
    // op1 != 10xx0
    } else {
      // Data-processing register (immediate shift) -- op4 == 0
      if (!enc.op4) {
        // op0 -> enc.op1 2 high order bits, op1 -> enc.op1 lowest bit
        // index is the concatenation of op0 and op1
        return kDataProcessingRI[(enc.op1 >> 2) | (enc.op1 & 0b1u)];
      // Data-processing register (register shift) -- op4 == 1
      } else {
        return kDataProcessingRR[(enc.op1 >> 2) | (enc.op1 & 0b1u)];
      }
    }
  // Data-processing immediate -- op0 == 1
  } else {
    // op0 -> enc.op1 2 high order bits, op1 -> enc.op1 2 lowest bits
    // index is the concatenation of op0 and op1
    return kDataProcessingI[(enc.op1 >> 1) | (enc.op1 & 0b11u)];
  }
}

// This is the top level of the instruction encoding schema for AArch32.
// Instructions are grouped into subsets based on this the top level and then
// into smaller sets.
//   cond op0 op1
//!= 1111 00x     Data-processing and miscellaneous instructions
//!= 1111 010     Load/Store Word, Unsigned Byte (immediate, literal)
//!= 1111 011 0   Load/Store Word, Unsigned Byte (register)
//!= 1111 011 1   Media instructions
//        10x     Branch, branch with link, and block data transfer
//        11x     System register access, Advanced SIMD, floating-point, and Supervisor call
//   1111 0xx     Unconditional instructions
static TryDecode * TryDecodeTopLevelEncodings(uint32_t bits) {
  const TopLevelEncodings enc = { bits };
  // op0 == 0xx
  if (!(enc.op0 >> 2)) {
    if (enc.cond != 0b1111u) {
      // Data-processing and miscellaneous instructions -- op0 == 00x
      if (!(enc.op0 >> 1)) {
        return TryDataProcessingAndMisc(bits);
      // Load/Store Word, Unsigned Byte (immediate, literal) -- op0 == 010
      } else if (enc.op0 == 0b010u) {
        const LoadStoreWUBIL enc_ls_word = { bits };
        return kLoadStoreWordUBIL[enc_ls_word.o2 << 1u | enc_ls_word.o1];
      // TODO(Sonya): Load/Store Word, Unsigned Byte (register) -- op0 == 011, op1 == 0
      } else if (!enc.op1) {
        // This should be returning another table index using a struct like above
        return nullptr;
      // TODO(Sonya): Media instructions -- op0 == 011, op1 == 1
      } else {
        // return a result from another function for instruction categorizing
        return nullptr;
      }
    // TODO(Sonya): Unconditional instructions -- cond == 1111
    } else {
      // return a result from another function for instruction categorizing
      return nullptr;
    }
  // op0 == 1xx
  } else {
    // Branch, branch with link, and block data transfer -- op0 == 10x
    if (enc.op0 >> 1 == 0b10u) {
      // Branch (immediate) op0 == 101
      if (enc.op0 == 0b101u) {
        return TryBranchImm;
      // TODO(Sonya): Exception Save/Restore -- cond == 1111, op0 == 100
      } else if (enc.cond == 0b1111u) {
        return nullptr;
      // TODO(Sonya): Load/Store Multiple -- cond != 1111, op0 == 100
      } else {
        return nullptr;
      }
    // TODO(Sonya): System register access, Advanced SIMD, floating-point, and Supervisor call -- op0 == 11x
    } else {
      // return a result from another function for instruction categorizing
      return nullptr;
    }
  }
}

static uint32_t BytesToBits(const uint8_t *bytes) {
  uint32_t bits = 0;
  bits = (bits << 8) | static_cast<uint32_t>(bytes[3]);
  bits = (bits << 8) | static_cast<uint32_t>(bytes[2]);
  bits = (bits << 8) | static_cast<uint32_t>(bytes[1]);
  bits = (bits << 8) | static_cast<uint32_t>(bytes[0]);
  return bits;
}
} // namespace

// Decode an instruction
bool AArch32Arch::DecodeInstruction(uint64_t address, std::string_view inst_bytes,
                                    Instruction &inst) const {

  inst.pc = address;
  inst.next_pc = address + inst_bytes.size();  // Default fall-through.
  inst.branch_taken_pc = 0;
  inst.branch_not_taken_pc = 0;
  inst.has_branch_taken_delay_slot = false;
  inst.has_branch_not_taken_delay_slot = false;
  inst.arch_name = arch_name;
  inst.arch = this;
  inst.category = Instruction::kCategoryInvalid;
  inst.operands.clear();
  if (!inst.bytes.empty() && inst.bytes.data() == inst_bytes.data()) {
    inst.bytes.resize(inst_bytes.size());
  } else {
    inst.bytes = inst_bytes;
  }

  if (address & 0b1u) {
    return false;
  }

  const auto bytes = reinterpret_cast<const uint8_t *>(inst.bytes.data());
  const auto bits = BytesToBits(bytes);

  auto decoder = TryDecodeTopLevelEncodings(bits);
  if (!decoder) {
    LOG(ERROR) << "unhandled bits";
    return false;
  }

  auto ret = decoder(inst, bits);
  LOG(ERROR) << inst.Serialize();
  return ret;
}

} // namespace remill
