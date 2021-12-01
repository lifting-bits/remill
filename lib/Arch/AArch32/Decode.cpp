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

#include <glog/logging.h>

#include <optional>

#include "Arch.h"
#include "remill/BC/ABI.h"

namespace remill {

namespace {

// Integer Data Processing (three register, register shift)
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

// Integer Data Processing (three register, immediate shift)
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

// Integer Data Processing (2 register and immediate, immediate shift)
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
    uint32_t _1001 : 4;
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
    uint32_t N : 1;
    uint32_t M : 1;
    uint32_t _1 : 1;
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

// Signed multiply, Divide
union SignedMulDiv {
  uint32_t flat;
  struct {
    uint32_t rn : 4;
    uint32_t _1 : 1;
    uint32_t op2 : 3;
    uint32_t rm : 4;
    uint32_t ra : 4;
    uint32_t rd : 4;
    uint32_t op1 : 3;
    uint32_t _01110 : 5;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(SignedMulDiv) == 4, " ");


// Load/Store Word, Unsigned Byte (immediate, literal)
union LoadStoreWUBIL {
  uint32_t flat;
  struct {
    uint32_t imm12 : 12;
    uint32_t rt : 4;
    uint32_t rn : 4;
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

// Load/Store Word, Unsigned Byte (register)
union LoadStoreWUBR {
  uint32_t flat;
  struct {
    uint32_t rm : 4;
    uint32_t _0 : 1;
    uint32_t type : 2;
    uint32_t imm5 : 5;
    uint32_t rt : 4;
    uint32_t rn : 4;
    uint32_t o1 : 1;
    uint32_t W : 1;
    uint32_t o2 : 1;
    uint32_t u : 1;
    uint32_t P : 1;
    uint32_t _011 : 3;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(LoadStoreWUBR) == 4, " ");

// Load/Store Dual, Half, Signed Byte (immediate, literal)
union LoadStoreDualHSBIL {
  uint32_t flat;
  struct {
    uint32_t imm4L : 4;
    uint32_t _1_b4 : 1;
    uint32_t op2 : 2;
    uint32_t _1_b7 : 1;
    uint32_t imm4H : 4;
    uint32_t rt : 4;
    uint32_t rn : 4;
    uint32_t o1 : 1;
    uint32_t W : 1;
    uint32_t _1_b22 : 1;
    uint32_t U : 1;
    uint32_t P : 1;
    uint32_t _000 : 3;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(LoadStoreDualHSBIL) == 4, " ");

// Load/Store Dual, Half, Signed Byte (register)
union LoadStoreDualHSBR {
  uint32_t flat;
  struct {
    uint32_t rm : 4;
    uint32_t _1_b4 : 1;
    uint32_t op2 : 2;
    uint32_t _1_b7 : 1;
    uint32_t _0000 : 4;
    uint32_t rt : 4;
    uint32_t rn : 4;
    uint32_t o1 : 1;
    uint32_t W : 1;
    uint32_t _0 : 1;
    uint32_t U : 1;
    uint32_t P : 1;
    uint32_t _000 : 3;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(LoadStoreDualHSBR) == 4, " ");

// Load/Store Multiple
union LoadStoreM {
  uint32_t flat;
  struct {
    uint32_t register_list : 16;
    uint32_t rn : 4;
    uint32_t L : 1;
    uint32_t W : 1;
    uint32_t op : 1;
    uint32_t U : 1;
    uint32_t P : 1;
    uint32_t _100 : 3;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(LoadStoreM) == 4, " ");


// Integer Test and Compare (two register, immediate shift)
union IntTestCompRRI {
  uint32_t flat;
  struct {
    uint32_t rm : 4;
    uint32_t _0 : 1;
    uint32_t type : 2;
    uint32_t imm5 : 5;
    uint32_t _0000 : 4;
    uint32_t rn : 4;
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
    uint32_t rn : 4;
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
    uint32_t rn : 4;
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
    uint32_t rm : 4;
    uint32_t _0 : 1;
    uint32_t type : 2;
    uint32_t imm5 : 5;
    uint32_t rd : 4;
    uint32_t rn : 4;
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
    uint32_t rm : 4;
    uint32_t _1 : 1;
    uint32_t type : 2;
    uint32_t _0 : 1;
    uint32_t rs : 4;
    uint32_t rd : 4;
    uint32_t rn : 4;
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
    uint32_t rn : 4;
    uint32_t s : 1;
    uint32_t opc : 2;
    uint32_t _00111 : 5;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(LogicalArithmeticRRI) == 4, " ");

union MoveHW {
  uint32_t flat;
  struct {
    uint32_t imm12 : 12;
    uint32_t rd : 4;
    uint32_t imm4 : 4;
    uint32_t _00 : 2;
    uint32_t H : 1;
    uint32_t _00110 : 5;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(MoveHW) == 4, " ");


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
    uint32_t _00010 : 5;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(Misc) == 4, " ");

// Media
union Media {
  uint32_t flat;
  struct {
    uint32_t _3_to_0 : 4;
    uint32_t _1 : 1;
    uint32_t op1 : 3;
    uint32_t _19_to_8 : 12;
    uint32_t op0 : 5;
    uint32_t _011 : 3;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(Media) == 4, " ");

// Integer Saturating Arithmetic
union IntSatArith {
  uint32_t flat;
  struct {
    uint32_t Rm : 4;
    uint32_t _11_to_4 : 8;
    uint32_t Rd : 4;
    uint32_t Rn : 4;
    uint32_t _0_b20 : 1;
    uint32_t opc : 2;
    uint32_t _00010 : 5;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(IntSatArith) == 4, " ");

// Saturate 16-bit
union Sat16 {
  uint32_t flat;
  struct {
    uint32_t Rn : 4;
    uint32_t _0011 : 4;
    uint32_t _1111 : 4;
    uint32_t Rd : 4;
    uint32_t sat_imm : 4;
    uint32_t _10 : 2;
    uint32_t U : 1;
    uint32_t _01101 : 5;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(Sat16) == 4, " ");

// Saturate 32-bit
union Sat32 {
  uint32_t flat;
  struct {
    uint32_t Rn : 4;
    uint32_t _01 : 2;
    uint32_t sh : 1;
    uint32_t imm5 : 5;
    uint32_t Rd : 4;
    uint32_t sat_imm : 5;
    uint32_t _1 : 1;
    uint32_t U : 1;
    uint32_t _01101 : 5;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(Sat32) == 4, " ");

// Extend and Add
union ExtAdd {
  uint32_t flat;
  struct {
    uint32_t Rm : 4;
    uint32_t _000111 : 6;
    uint32_t rot : 2;
    uint32_t Rd : 4;
    uint32_t Rn : 4;
    uint32_t op : 2;
    uint32_t U : 1;
    uint32_t _01101 : 5;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(ExtAdd) == 4, " ");

// Bitfield Insert
union BitInsert {
  uint32_t flat;
  struct {
    uint32_t Rn : 4;
    uint32_t _001 : 3;
    uint32_t lsb : 5;
    uint32_t Rd : 4;
    uint32_t msb : 5;
    uint32_t _0111110 : 7;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(BitInsert) == 4, " ");


// Bitfield Extract
union BitExt {
  uint32_t flat;
  struct {
    uint32_t Rn : 4;
    uint32_t _101 : 3;
    uint32_t lsb : 5;
    uint32_t Rd : 4;
    uint32_t widthm1 : 5;
    uint32_t _1 : 1;
    uint32_t U : 1;
    uint32_t _01111 : 5;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(BitExt) == 4, " ");

// Reverse Bit/Byte
union RevBitByte {
  uint32_t flat;
  struct {
    uint32_t Rm : 4;
    uint32_t _011 : 3;
    uint32_t o2 : 1;
    uint32_t _11_to_8 : 4;
    uint32_t Rd : 4;
    uint32_t _19_to_16 : 4;
    uint32_t _11 : 2;
    uint32_t o1 : 1;
    uint32_t _01101 : 5;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(RevBitByte) == 4, " ");


// Move Special Register and Hints (immediate)
union SpecialRegsAndHints {
  uint32_t flat;
  struct {
    uint32_t imm12 : 12;
    uint32_t _1111 : 4;
    uint32_t imm4 : 4;
    uint32_t _10 : 2;
    uint32_t R : 1;
    uint32_t _00110 : 5;
    uint32_t cond : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(SpecialRegsAndHints) == 4, " ");

static constexpr auto kAddressSize = 32u;
static constexpr auto kPCRegNum = 15u;
static constexpr auto kLRRegNum = 14u;

static const char *const kIntRegName[] = {
    "R0", "R1", "R2",  "R3",  "R4",  "R5",  "R6",  "R7",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"};

typedef bool(TryDecode)(Instruction &, uint32_t);
typedef std::optional<uint32_t>(InstEval)(uint32_t, uint32_t);

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
                      uint64_t size = 32,
                      Operand::Action action = Operand::kActionRead) {
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

static void
AddShiftOp(Instruction &inst, Operand::ShiftRegister::Shift shift_op,
           const char *reg_name, unsigned reg_size, unsigned shift_size,
           bool can_shift_op_size = false) {
  Operand::ShiftRegister shift_reg;
  shift_reg.reg.name = reg_name;
  shift_reg.reg.size = reg_size;
  shift_reg.shift_op = shift_op;
  shift_reg.shift_size = shift_size;
  shift_reg.can_shift_op_size = can_shift_op_size;
  auto &op = inst.EmplaceOperand(shift_reg);
  op.action = Operand::kActionRead;
}

static void AddShiftThenExtractOp(Instruction &inst,
                                  Operand::ShiftRegister::Shift shift_op,
                                  Operand::ShiftRegister::Extend extend_op,
                                  const char *reg_name, unsigned reg_size,
                                  unsigned shift_size, unsigned extract_size,
                                  bool can_shift_op_size = false) {
  Operand::ShiftRegister shift_reg;
  shift_reg.reg.name = reg_name;
  shift_reg.reg.size = reg_size;
  shift_reg.shift_op = shift_op;
  shift_reg.shift_size = shift_size;
  shift_reg.can_shift_op_size = can_shift_op_size;
  shift_reg.extract_size = extract_size;
  shift_reg.extend_op = extend_op;
  shift_reg.shift_first = true;
  auto &op = inst.EmplaceOperand(shift_reg);
  op.action = Operand::kActionRead;
}

// static void AddExtractThenShiftOp(Instruction &inst,
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
// }


// Note: Order is significant; extracted bits may be casted to this type.
enum Shift : uint32_t { kShiftLSL, kShiftLSR, kShiftASR, kShiftROR };

// Translate a shift encoding into an operand shift type used by the shift
// register class.
static Operand::ShiftRegister::Shift GetOperandShift(Shift s) {
  switch (s) {
    case kShiftLSL: return Operand::ShiftRegister::kShiftLeftWithZeroes;
    case kShiftLSR: return Operand::ShiftRegister::kShiftUnsignedRight;
    case kShiftASR: return Operand::ShiftRegister::kShiftSignedRight;
    case kShiftROR: return Operand::ShiftRegister::kShiftRightAround;
  }
  return Operand::ShiftRegister::kShiftInvalid;
}

// Do an extraction and zero extension on an expression
template <unsigned ext = llvm::Instruction::ZExt>
static OperandExpression *
ExtractAndExtExpr(Instruction &inst, OperandExpression *op_expr,
                  unsigned int extract_size, unsigned int extend_size) {
  auto extract_type =
      llvm::Type::getIntNTy(*(inst.arch->context), extract_size);
  auto extend_type = llvm::Type::getIntNTy(*(inst.arch->context), extend_size);

  // Extract bits
  op_expr =
      inst.EmplaceUnaryOp(llvm::Instruction::Trunc, op_expr, extract_type);

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
      inst.operands.back().expr =
          ExtractAndExtExpr(inst, inst.operands.back().expr, 1u, 8u);
    } else {
      AddImmOp(inst,
               (unrotated_value >> ((rotation_amount + 31u) % 32u)) & 0b1u);
    }
  }
}

static OperandExpression *RORExpr(Instruction &inst, OperandExpression *op_expr,
                                  OperandExpression *shift_amount) {
  const auto word_type = inst.arch->AddressType();
  const auto _32 = llvm::ConstantInt::get(word_type, 32u, false);

  shift_amount = inst.EmplaceBinaryOp(llvm::Instruction::URem, shift_amount,
                                      inst.EmplaceConstant(_32));
  auto lhs_expr =
      inst.EmplaceBinaryOp(llvm::Instruction::LShr, op_expr, shift_amount);
  auto rhs_expr = inst.EmplaceBinaryOp(
      llvm::Instruction::Shl, op_expr,
      inst.EmplaceBinaryOp(llvm::Instruction::Sub, inst.EmplaceConstant(_32),
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
      shift_val_expr_c = inst.EmplaceBinaryOp(
          llvm::Instruction::Sub, shift_val_expr_c, inst.EmplaceConstant(_1));
      carry_expr = inst.EmplaceBinaryOp(llvm::Instruction::AShr, carry_expr,
                                        shift_val_expr_c);
      break;
    case Shift::kShiftLSL:

      // 32u - shift_size
      shift_val_expr_c = inst.EmplaceBinaryOp(
          llvm::Instruction::Sub, inst.EmplaceConstant(_32), shift_val_expr_c);
      carry_expr = inst.EmplaceBinaryOp(llvm::Instruction::LShr, carry_expr,
                                        shift_val_expr_c);
      break;
    case Shift::kShiftLSR:

      // shift_size - 1u
      shift_val_expr_c = inst.EmplaceBinaryOp(
          llvm::Instruction::Sub, shift_val_expr_c, inst.EmplaceConstant(_1));
      carry_expr = inst.EmplaceBinaryOp(llvm::Instruction::LShr, carry_expr,
                                        shift_val_expr_c);
      break;
    case Shift::kShiftROR:

      // (shift_size + 31u) % 32u
      shift_val_expr_c = inst.EmplaceBinaryOp(
          llvm::Instruction::Add, shift_val_expr_c, inst.EmplaceConstant(_31));
      shift_val_expr_c = inst.EmplaceBinaryOp(
          llvm::Instruction::URem, shift_val_expr_c, inst.EmplaceConstant(_32));
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
      op_expr =
          inst.EmplaceBinaryOp(llvm::Instruction::Shl, op_expr, shift_val_expr);
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
static void AddShiftImmCarryOperand(Instruction &inst, uint32_t reg_num,
                                    uint32_t shift_type, uint32_t shift_size,
                                    const char *carry_reg_name) {
  auto is_rrx = false;
  if (!shift_size && shift_type == Shift::kShiftROR) {
    shift_size = 1;
    is_rrx = true;
  }

  if (!shift_size) {
    AddIntRegOp(inst, carry_reg_name, 8u, Operand::kActionRead);
    inst.operands.back().expr =
        ExtractAndExtExpr(inst, inst.operands.back().expr, 1u, 8u);
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
          inst.operands.back().expr =
              ExtractAndExtExpr(inst, inst.operands.back().expr, 1u, 32u);
        } else {
          AddShiftThenExtractOp(
              inst, Operand::ShiftRegister::kShiftUnsignedRight,
              Operand::ShiftRegister::kExtendUnsigned, kIntRegName[reg_num], 32,
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
                                  bool carry_out, bool can_shift_right_by_32) {
  auto is_rrx = false;
  auto can_shift_op_size = false;
  if (!shift_size && shift_type == Shift::kShiftROR) {
    shift_size = 1;
    is_rrx = true;
  } else if (shift_type == Shift::kShiftLSR || shift_type == Shift::kShiftASR) {
    if (!shift_size) {
      shift_size = 32;
    }
    if (can_shift_right_by_32) {
      can_shift_op_size = true;
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
                 kIntRegName[reg_num], 32, shift_size, can_shift_op_size);
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
    inst.operands.back().expr = inst.EmplaceBinaryOp(
        llvm::Instruction::Or, inst.operands.back().expr, rrx_op);
  }

  if (carry_out) {
    AddShiftImmCarryOperand(inst, reg_num, shift_type, shift_size, "C");
  }
}

// Decode the condition field and fill in the instruction conditions accordingly
static bool DecodeCondition(Instruction &inst, uint32_t cond) {

  auto _8_type = llvm::Type::getInt8Ty(*inst.arch->context);
  const auto _1 = llvm::ConstantInt::get(_8_type, 1u, false);

  bool negate_conditions = false;
  bool is_cond = true;

  OperandExpression *op_expr = nullptr;
  switch (cond) {
    case 0b0001: negate_conditions = true; [[clang::fallthrough]];
    case 0b0000: {
      op_expr = inst.EmplaceRegister("Z");
      break;
    }
    case 0b0011: negate_conditions = true; [[clang::fallthrough]];
    case 0b0010: {
      op_expr = inst.EmplaceRegister("C");
      break;
    }
    case 0b0101: negate_conditions = true; [[clang::fallthrough]];
    case 0b0100: {
      op_expr = inst.EmplaceRegister("N");
      break;
    }
    case 0b0111: negate_conditions = true; [[clang::fallthrough]];
    case 0b0110: {
      op_expr = inst.EmplaceRegister("V");
      break;
    }
    case 0b1001: negate_conditions = true; [[clang::fallthrough]];
    case 0b1000: {
      auto c_expr = inst.EmplaceRegister("C");
      auto z_expr = inst.EmplaceRegister("Z");
      z_expr = inst.EmplaceBinaryOp(llvm::Instruction::Xor, z_expr,
                                    inst.EmplaceConstant(_1));
      op_expr = inst.EmplaceBinaryOp(llvm::Instruction::And, z_expr, c_expr);
      break;
    }
    case 0b1011: negate_conditions = true; [[clang::fallthrough]];
    case 0b1010: {
      auto n_expr = inst.EmplaceRegister("N");
      auto v_expr = inst.EmplaceRegister("V");
      op_expr = inst.EmplaceBinaryOp(llvm::Instruction::Xor, n_expr, v_expr);
      op_expr = inst.EmplaceBinaryOp(llvm::Instruction::Xor, op_expr,
                                     inst.EmplaceConstant(_1));
      break;
    }
    case 0b1101: negate_conditions = true; [[clang::fallthrough]];
    case 0b1100: {
      auto n_expr = inst.EmplaceRegister("N");
      auto v_expr = inst.EmplaceRegister("V");
      op_expr = inst.EmplaceBinaryOp(llvm::Instruction::Xor, n_expr, v_expr);
      op_expr = inst.EmplaceBinaryOp(llvm::Instruction::Xor, op_expr,
                                     inst.EmplaceConstant(_1));
      auto z_expr = inst.EmplaceRegister("Z");
      z_expr = inst.EmplaceBinaryOp(llvm::Instruction::Xor, z_expr,
                                    inst.EmplaceConstant(_1));
      op_expr = inst.EmplaceBinaryOp(llvm::Instruction::And, z_expr, op_expr);
      break;
    }
    case 0b1111:
    case 0b1110:
      op_expr = inst.EmplaceConstant(_1);
      is_cond = false;
      break;
    default:
      LOG(FATAL) << "Invalid condition bits " << cond << " in "
                 << inst.Serialize();
      break;
  }

  if (negate_conditions) {
    op_expr = inst.EmplaceBinaryOp(llvm::Instruction::Xor, op_expr,
                                   inst.EmplaceConstant(_1));
  }

  AddExprOp(inst, op_expr, 8u);
  AddExprOp(inst, inst.EmplaceVariable(kBranchTakenVariableName, _8_type), 8u,
            Operand::kActionWrite);

  return is_cond;
}

std::optional<uint64_t> EvalReg(const Instruction &inst,
                                const Operand::Register &op,
                                bool &uses_linkreg) {
  if (!uses_linkreg) {
    uses_linkreg = (op.name == kIntRegName[kLRRegNum] || op.name == "LR");
  }

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
    case Operand::ShiftRegister::kShiftInvalid: return maybe_val;
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
    default: return std::nullopt;
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
    case Operand::ShiftRegister::kExtendInvalid: return maybe_val;
    case Operand::ShiftRegister::kExtendSigned: {
      val &= (1u << (op.extract_size)) - 1u;
      auto sign = val >> (op.extract_size - 1u);

      if (sign) {
        val |= ~0u << op.extract_size;
      }

      return val;
    }
    case Operand::ShiftRegister::kExtendUnsigned:
      return val & ((1u << (op.extract_size)) - 1u);
    default: return std::nullopt;
  }
}

std::optional<uint64_t> EvalOperand(const Instruction &inst, const Operand &op,
                                    bool &uses_linkreg) {
  switch (op.type) {
    case Operand::kTypeInvalid: return std::nullopt;
    case Operand::kTypeImmediate: return op.imm.val;
    case Operand::kTypeRegister: return EvalReg(inst, op.reg, uses_linkreg);
    case Operand::kTypeAddress: {
      auto seg_val = EvalReg(inst, op.addr.segment_base_reg, uses_linkreg);
      auto base_val = EvalReg(inst, op.addr.base_reg, uses_linkreg);
      auto index_val = EvalReg(inst, op.addr.index_reg, uses_linkreg);

      if (!seg_val || !base_val || !index_val) {
        return std::nullopt;
      }

      return static_cast<uint64_t>(
          static_cast<int64_t>(*seg_val) + static_cast<int64_t>(*base_val) +
          (static_cast<int64_t>(*index_val) * op.addr.scale) +
          op.addr.displacement);
    }
    case Operand::kTypeShiftRegister: {
      if (op.shift_reg.shift_first) {
        return EvalExtract(
            op.shift_reg,
            EvalShift(op.shift_reg,
                      EvalReg(inst, op.shift_reg.reg, uses_linkreg)));
      } else {
        return EvalShift(
            op.shift_reg,
            EvalExtract(op.shift_reg,
                        EvalReg(inst, op.shift_reg.reg, uses_linkreg)));
      }
    }
    case Operand::kTypeRegisterExpression:
      return EvalReg(inst, op.reg, uses_linkreg);
    default: return std::nullopt;
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

      // HACK(akshayk): EvalPCDest is only getting called from the instruction
      //                decode function emplace 5 operands to the vector. Added
      //                assert check to make sure it is not getting called else
      //                where. Update it to pass source operand as parameter
      //                and use them to identify the instruction category
      CHECK(inst.operands.size() == 5)
          << "Failed to evaluate PC registers due to missing source operands;";


      // NOTE(akshayk): LR register can be used in source expression to update PC.
      //                These instructions will be of return type. Check if either
      //                of the operand uses link register to update the PC
      //  e.g: add pc, lr, #4
      //
      bool uses_linkreg = false;
      auto src1 = EvalOperand(inst, inst.operands[3], uses_linkreg);
      auto src2 = EvalOperand(inst, inst.operands[4], uses_linkreg);

      AddAddrRegOp(inst, kNextPCVariableName.data(), kAddressSize,
                   Operand::kActionWrite, 0);

      if (uses_linkreg) {

        // NOTE(akshayk): conditional return `movne pc, lr`
        if (is_cond) {
          inst.branch_not_taken_pc = inst.next_pc;
          inst.category = Instruction::kCategoryConditionalFunctionReturn;
        } else {
          inst.category = Instruction::kCategoryFunctionReturn;
        }
      } else if (!src1 || !src2) {
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
    AddAddrRegOp(inst, kIgnoreNextPCVariableName.data(), kAddressSize,
                 Operand::kActionWrite, 0);
    inst.category = Instruction::kCategoryNormal;
  }
  return true;
}

// High 3 bit opc
static InstEval *kIdpEvaluators[] = {
    [0b000] =
        +[](uint32_t src1, uint32_t src2) {
          return std::optional<uint32_t>(src1 & src2);
        },
    [0b001] =
        +[](uint32_t src1, uint32_t src2) {
          return std::optional<uint32_t>(src1 ^ src2);
        },
    [0b010] =
        +[](uint32_t src1, uint32_t src2) {
          return std::optional<uint32_t>(src1 - src2);
        },
    [0b011] =
        +[](uint32_t src1, uint32_t src2) {
          return std::optional<uint32_t>(src2 - src1);
        },
    [0b100] =
        +[](uint32_t src1, uint32_t src2) {
          return std::optional<uint32_t>(src2 + src1);
        },
    [0b101] =
        +[](uint32_t src1, uint32_t src2) {
          return std::optional<uint32_t>(std::nullopt);
        },
    [0b110] =
        +[](uint32_t src1, uint32_t src2) {
          return std::optional<uint32_t>(std::nullopt);
        },
    [0b111] =
        +[](uint32_t src1, uint32_t src2) {
          return std::optional<uint32_t>(std::nullopt);
        },
};

// High 3 bit opc and low bit s, opc:s
static const char *const kIdpNamesRRR[] = {
    [0b0000] = "ANDrr",  [0b0001] = "ANDSrr", [0b0010] = "EORrr",
    [0b0011] = "EORSrr", [0b0100] = "SUBrr",  [0b0101] = "SUBSrr",
    [0b0110] = "RSBrr",  [0b0111] = "RSBSrr", [0b1000] = "ADDrr",
    [0b1001] = "ADDSrr", [0b1010] = "ADCrr",  [0b1011] = "ADCSrr",
    [0b1100] = "SBCrr",  [0b1101] = "SBCSrr", [0b1110] = "RSCrr",
    [0b1111] = "RSCSrr"};

// 000     AND, ANDS (register)
// 001     EOR, EORS (register)
// 010 0 != 1101 SUB, SUBS (register) — SUB
// 010 0 1101  SUB, SUBS (SP minus register) — SUB
// 010 1 != 1101 SUB, SUBS (register) — SUBS
// 010 1 1101  SUB, SUBS (SP minus register) — SUBS
// 011     RSB, RSBS (register)
// 100 0 != 1101 ADD, ADDS (register) — ADD
// 100 0 1101  ADD, ADDS (SP plus register) — ADD
// 100 1 != 1101 ADD, ADDS (register) — ADDS
// 100 1 1101  ADD, ADDS (SP plus register) — ADDS
// 101     ADC, ADCS (register)
// 110     SBC, SBCS (register)
// 111     RSC, RSCS (register)
static bool TryDecodeIntegerDataProcessingRRRI(Instruction &inst,
                                               uint32_t bits) {
  const IntDataProcessingRRRI enc = {bits};
  inst.function = kIdpNamesRRR[(enc.opc << 1u) | enc.s];
  auto is_cond = DecodeCondition(inst, enc.cond);
  AddIntRegOp(inst, enc.rd, 32, Operand::kActionWrite);
  AddIntRegOp(inst, enc.rn, 32, Operand::kActionRead);
  AddShiftRegImmOperand(inst, enc.rm, enc.type, enc.imm5, enc.s, true);
  return EvalPCDest(inst, enc.s, enc.rd, kIdpEvaluators[enc.opc], is_cond);
}

// Integer Data Processing (three register, register shift)
static bool TryDecodeIntegerDataProcessingRRRR(Instruction &inst,
                                               uint32_t bits) {
  const IntDataProcessingRRRR enc = {bits};

  if (enc.rn == kPCRegNum || enc.rd == kPCRegNum || enc.rs == kPCRegNum ||
      enc.rm == kPCRegNum) {
    inst.category = Instruction::kCategoryError;
    return false;
  }

  inst.function = kIdpNamesRRR[(enc.opc << 1u) | enc.s];
  DecodeCondition(inst, enc.cond);

  AddIntRegOp(inst, enc.rd, 32, Operand::kActionWrite);
  AddIntRegOp(inst, enc.rn, 32, Operand::kActionRead);
  AddShiftRegRegOperand(inst, enc.rm, enc.type, enc.rs, enc.s);
  AddAddrRegOp(inst, kIgnoreNextPCVariableName.data(), kAddressSize,
               Operand::kActionWrite, 0);

  inst.category = Instruction::kCategoryNormal;
  return true;
}

// 000           AND, ANDS (immediate)
// 001           EOR, EORS (immediate)
// 010 0 != 11x1 SUB, SUBS (immediate) — SUB
// 010 0    1101 SUB, SUBS (SP minus immediate) — SUB
// 010 0    1111 ADR — A2 (alias of subtract)
// 010 1 != 1101 SUB, SUBS (immediate) — SUBS
// 010 1    1101 SUB, SUBS (SP minus immediate) — SUBS
// 011           RSB, RSBS (immediate)
// 100 0 != 11x1 ADD, ADDS (immediate) — ADD
// 100 0    1101 ADD, ADDS (SP plus immediate) — ADD
// 100 0    1111 ADR — A1 (alias of add)
// 100 1 != 1101 ADD, ADDS (immediate) — ADDS
// 100 1    1101 ADD, ADDS (SP plus immediate) — ADDS
// 101           ADC, ADCS (immediate)
// 110           SBC, SBCS (immediate)
// 111           RSC, RSCS (immediate)
static bool TryDecodeIntegerDataProcessingRRI(Instruction &inst,
                                              uint32_t bits) {
  const IntDataProcessingRRI enc = {bits};

  inst.function = kIdpNamesRRR[(enc.opc << 1u) | enc.s];
  auto is_cond = DecodeCondition(inst, enc.cond);
  AddIntRegOp(inst, enc.rd, kAddressSize, Operand::kActionWrite);

  // Raise the program counter to align to a multiple of 4 bytes
  if (enc.rn == kPCRegNum && (enc.opc == 0b100u || enc.opc == 0b010u)) {
    int64_t diff =
        static_cast<int32_t>(inst.pc & ~(3u)) - static_cast<int32_t>(inst.pc);
    AddAddrRegOp(inst, kPCVariableName.data(), kAddressSize,
                 Operand::kActionRead, diff);
  } else {
    AddIntRegOp(inst, enc.rn, kAddressSize, Operand::kActionRead);
  }

  ExpandTo32AddImmAddCarry(inst, enc.imm12, enc.s);

  return EvalPCDest(inst, enc.s, enc.rd, kIdpEvaluators[enc.opc], is_cond);
}

static const char *const kMulAccRRR[] = {
    [0b0000] = "MUL",    [0b0001] = "MULS",   [0b0010] = "MLA",
    [0b0011] = "MLAS",   [0b0100] = "UMAAL",  [0b0101] = nullptr,
    [0b0110] = "MLS",    [0b0111] = nullptr,  [0b1000] = "UMULL",
    [0b1001] = "UMULLS", [0b1010] = "UMLAL",  [0b1011] = "UMLALS",
    [0b1100] = "SMULL",  [0b1101] = "SMULLS", [0b1110] = "SMLAL",
    [0b1111] = "SMLALS"};

// 000   MUL, MULS
// 001   MLA, MLAS
// 010 0 UMAAL - writes to RdHi + RdLo, read RdHi
// 010 1 UNALLOCATED
// 011 0 MLS
// 011 1 UNALLOCATED
// 100   UMULL, UMULLS - writes to RdHi + RdLo
// 101   UMLAL, UMLALS - writes to RdHi + RdLo, read RdHi
// 110   SMULL, SMULLS - writes to RdHi + RdLo
// 111   SMLAL, SMLALS - writes to RdHi + RdLo, read RdHi
static bool TryDecodeMultiplyAndAccumulate(Instruction &inst, uint32_t bits) {
  const MultiplyAndAccumulate enc = {bits};

  // MUL, MULS only: if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;
  // All other instructions: if d == 15 || n == 15 || m == 15 || a == 15 then UNPREDICTABLE;
  if (enc.rdhi == kPCRegNum || (enc.rdlo == kPCRegNum && !enc.opc) ||
      enc.rn == kPCRegNum || enc.rm == kPCRegNum) {
    inst.category = Instruction::kCategoryError;
    return false;
  }

  auto instruction = kMulAccRRR[(enc.opc << 1u) | enc.s];
  if (!instruction) {
    inst.category = Instruction::kCategoryError;
    return false;
  }
  inst.function = instruction;
  DecodeCondition(inst, enc.cond);

  AddIntRegOp(inst, enc.rdhi, 32, Operand::kActionWrite);

  // 2nd write reg only needed for instructions with an opc that begins with 1 and UMALL
  if (((enc.opc >> 2) & 0b1u) || enc.opc == 0b010u) {

    // if dHi == dLo then UNPREDICTABLE;
    if (enc.rdlo == enc.rdhi) {
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

static const char *const kHMulAccRRR[] = {
    [0b0000] = "SMLABB",  // (M == 0 && N == 0)
    [0b0010] = "SMLABT",  // (M == 1 && N == 0)
    [0b0001] = "SMLATB",  // (M == 0 && N == 1)
    [0b0011] = "SMLATT",  // (M == 1 && N == 1)
    [0b0100] = "SMLAWB",  [0b0101] = "SMULWB",
    [0b0110] = "SMLAWT",  [0b0111] = "SMULWT",
    [0b1000] = "SMLALBB",  // (M == 0 && N == 0)
    [0b1010] = "SMLALBT",  // (M == 1 && N == 0)
    [0b1001] = "SMLALTB",  // (M == 0 && N == 1)
    [0b1011] = "SMLALTT",  // (M == 1 && N == 1)
    [0b1100] = "SMULBB",  // (M == 0 && N == 0)
    [0b1110] = "SMULBT",  // (M == 1 && N == 0)
    [0b1101] = "SMULTB",  // (M == 0 && N == 1)
    [0b1111] = "SMULTT",  // (M == 1 && N == 1)
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

  const HMultiplyAndAccumulate enc = {bits};
  bool add_ra = enc.opc == 0b10u || (enc.opc == 0b1u && !enc.N) || !enc.opc;

  // if d == 15 || n == 15 || m == 15 || a == 15 then UNPREDICTABLE;
  // if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;
  // if dHi == dLo then UNPREDICTABLE;
  if (enc.rd == kPCRegNum || enc.rn == kPCRegNum || enc.rm == kPCRegNum ||
      ((enc.ra == kPCRegNum) && add_ra) ||
      ((enc.opc == 0b10u) && (enc.rd == enc.ra))) {
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
    inst.operands.back().expr =
        inst.EmplaceBinaryOp(llvm::Instruction::AShr, inst.operands.back().expr,
                             inst.EmplaceConstant(_16));
  } else {
    inst.operands.back().expr = ExtractAndExtExpr<llvm::Instruction::SExt>(
        inst, inst.operands.back().expr, 16u, 32u);
  }

  // Ra
  if (add_ra) {
    AddIntRegOp(inst, enc.ra, 32, Operand::kActionRead);
  }

  inst.category = Instruction::kCategoryNormal;
  return true;
}

// Index from: op1 | Ra == 15 | op2
static const char *kSMulDiv(uint32_t index) {
  switch (index) {
    case 0b0000000: return "SMLAD";
    case 0b0000001: return "SMLADX";
    case 0b0000010: return "SMLSD";
    case 0b0000011: return "SMLSDX";
    case 0b0001000: return "SMUAD";
    case 0b0001001: return "SMUADX";
    case 0b0001010: return "SMUSD";
    case 0b0001011: return "SMUSDX";

    // case 0b0010000: - Note(Sonya): a != 15 is constrained UNPREDICTABLE
    case 0b0011000: return "SDIV";

    // case 0b0110000: - Note(Sonya): a != 15 is constrained UNPREDICTABLE
    case 0b0111000: return "UDIV";
    case 0b1000000:
    case 0b1001000: return "SMLALD";
    case 0b1000001:
    case 0b1001001: return "SMLALDX";
    case 0b1000010:
    case 0b1001010: return "SMLSLD";
    case 0b1000011:
    case 0b1001011: return "SMLSLDX";
    case 0b1010000: return "SMMLA";
    case 0b1010001: return "SMMLAR";
    case 0b1010110:

      // case 0b1011110: - Note(Sonya): a == 15 is constrained UNPREDICTABLE
      return "SMMLS";
    case 0b1010111:

      // case 0b1011111: - Note(Sonya): a == 15 is constrained UNPREDICTABLE
      return "SMMLSR";
    case 0b1011000: return "SMMUL";
    case 0b1011001: return "SMMULR";
    default: return nullptr;  // UNALLOCATED
  }
}

// op1 Ra      op2
// 000 != 1111 000 SMLAD, SMLADX — SMLAD     if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;
// 000 != 1111 001 SMLAD, SMLADX — SMLADX    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;
// 000 != 1111 010 SMLSD, SMLSDX — SMLSD     if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;
// 000 != 1111 011 SMLSD, SMLSDX — SMLSDX    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;
// 000         1xx UNALLOCATED
// 000   1111  000 SMUAD, SMUADX — SMUAD     if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;  // add 0 TODO
// 000   1111  001 SMUAD, SMUADX — SMUADX    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;
// 000   1111  010 SMUSD, SMUSDX — SMUSD     if d == 15 || n == 15 || m == 15 then UNPREDICTABLE; // add 0 TODO
// 000   1111  011 SMUSD, SMUSDX — SMUSDX    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;
// 001         000 SDIV                      if d == 15 || n == 15 || m == 15 || a != 15 then UNPREDICTABLE;
// 001      != 000 UNALLOCATED
// 010             UNALLOCATED
// 011         000 UDIV                      if d == 15 || n == 15 || m == 15 || a != 15 then UNPREDICTABLE;
// 011      != 000 UNALLOCATED
// 100         000 SMLALD, SMLALDX — SMLALD  if dLo == 15 || dHi == 15 || n == 15 || m == 15 || dHi == dLo then UNPREDICTABLE;
// 100         001 SMLALD, SMLALDX — SMLALDX if dLo == 15 || dHi == 15 || n == 15 || m == 15 || dHi == dLo then UNPREDICTABLE;
// 100         010 SMLSLD, SMLSLDX — SMLSLD  if dLo == 15 || dHi == 15 || n == 15 || m == 15 || dHi == dLo then UNPREDICTABLE;
// 100         011 SMLSLD, SMLSLDX — SMLSLDX if dLo == 15 || dHi == 15 || n == 15 || m == 15 || dHi == dLo then UNPREDICTABLE;
// 100         1xx UNALLOCATED
// 101 != 1111 000 SMMLA, SMMLAR — SMMLA     if d == 15 || n == 15 || m == 15 then UNPREDICTABLE; // add 0x0
// 101 != 1111 001 SMMLA, SMMLAR — SMMLAR    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE; // add 0x80000000
// 101         01x UNALLOCATED
// 101         10x UNALLOCATED
// 101         110 SMMLS, SMMLSR — SMMLS     if d == 15 || n == 15 || m == 15 || a == 15 then UNPREDICTABLE; // add 0x0
// 101         111 SMMLS, SMMLSR — SMMLSR    if d == 15 || n == 15 || m == 15 || a == 15 then UNPREDICTABLE; // add 0x80000000
// 101   1111  000 SMMUL, SMMULR — SMMUL     if d == 15 || n == 15 || m == 15 then UNPREDICTABLE; // add 0 add 0x0
// 101   1111  001 SMMUL, SMMULR — SMMULR    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE; // add 0 add 0x80000000
// 11x             UNALLOCATED
// Signed multiply, Divide
static bool TryDecodeSignedMultiplyDivide(Instruction &inst, uint32_t bits) {
  const SignedMulDiv enc = {bits};

  auto instruction =
      kSMulDiv(enc.op1 << 4 | (enc.ra == kPCRegNum) << 3 | enc.op2);
  if (!instruction || enc.rd == kPCRegNum || enc.rn == kPCRegNum ||
      enc.rm == kPCRegNum ||
      (enc.op1 == 0b100 && (enc.ra == kPCRegNum || enc.ra == enc.rd))) {
    inst.category = Instruction::kCategoryError;
    return false;
  }
  inst.function = instruction;
  DecodeCondition(inst, enc.cond);
  auto div = enc.op1 == 0b001 || enc.op1 == 0b011;

  if (enc.op1 == 0b100) {
    AddIntRegOp(inst, enc.ra, 32, Operand::kActionWrite);
  }
  AddIntRegOp(inst, enc.rd, 32, Operand::kActionWrite);
  AddIntRegOp(inst, enc.rn, 32, Operand::kActionRead);
  AddIntRegOp(inst, enc.rm, 32, Operand::kActionRead);

  // MSwap
  if ((enc.op1 == 0b100 || !enc.op1) && (enc.op2 & 0b1)) {
    const auto word_type = inst.arch->AddressType();
    const auto _16 = llvm::ConstantInt::get(word_type, 16u, false);
    inst.operands.back().expr =
        RORExpr(inst, inst.operands.back().expr, inst.EmplaceConstant(_16));
  }

  if (!div && enc.ra != kPCRegNum) {
    AddIntRegOp(inst, enc.ra, 32, Operand::kActionRead);
  } else if (!div) {
    AddImmOp(inst, 0, 32u, true);
  }

  if (enc.op1 == 0b100) {
    AddIntRegOp(inst, enc.rd, 32, Operand::kActionRead);
  }

  // Round
  if (enc.op1 == 0b101 && (enc.op2 & 0b1)) {
    AddImmOp(inst, 0x80000000, 32u, false);
  } else if (enc.op1 == 0b101) {
    AddImmOp(inst, 0, 32u, true);
  }

  inst.category = Instruction::kCategoryNormal;
  return true;
}

static const char *const kLoadSWUB[] = {
    [0b0000] = "STRp",  [0b0001] = "LDRp",  [0b0010] = "STRBp",
    [0b0011] = "LDRBp", [0b0100] = "STRT",  [0b0101] = "LDRT",
    [0b0110] = "STRBT", [0b0111] = "LDRBT", [0b1000] = "STR",
    [0b1001] = "LDR",   [0b1010] = "STRB",  [0b1011] = "LDRB",
    [0b1100] = "STRp",  [0b1101] = "LDRp",  [0b1110] = "STRBp",
    [0b1111] = "LDRBp",
};

// P:W o2 o1    Rn
// != 01 0 1    1111 LDR (literal)
// != 01 1 1    1111 LDRB (literal)
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
template <Operand::Action kMemAction, Operand::Action kRegAction,
          unsigned kMemSize, bool kAlignPC = false>
static bool TryDecodeLoadStoreWordUBIL(Instruction &inst, uint32_t bits) {
  const LoadStoreWUBIL enc = {bits};

  bool write_back = (!enc.P || enc.W);
  bool is_add = enc.u;
  bool is_index = enc.P;
  if (write_back && (enc.rn == kPCRegNum || enc.rn == enc.rt)) {
    inst.category = Instruction::kCategoryError;
    return false;
  }

  inst.function = kLoadSWUB[enc.P << 3u | enc.W << 2u | enc.o2 << 1u | enc.o1];
  auto is_cond = DecodeCondition(inst, enc.cond);

  // LDR & LDRB (literal) are pc relative. Need to align the PC to the next nearest 4 bytes
  int64_t pc_adjust = 0;
  if (kAlignPC && enc.rn == kPCRegNum) {
    pc_adjust =
        static_cast<int32_t>(inst.pc & ~(3u)) - static_cast<int32_t>(inst.pc);
  }
  auto disp = static_cast<int64_t>(enc.imm12);

  // Subtract
  if (!is_add) {
    disp = -disp;
  }

  //  NOTE(akshayk): The PC of the instruction being fetched is generally of the PC of the
  //                 executing instruction. This is the legacy pipeline effect which the ARM
  //                 processor carry. The PC during an instruction execution you see will be
  //                 "address of the executing instruction +8" for ARM and "address of the
  //                 executing instruction +4" for Thumb; The decoder should also handle it
  //                 and add offset to `disp`
  //
  //  TODO(akshayk): Decoder does not support thumb architecture; use offset 8 for the ARM;
  //                 Update it accordingly after adding support for thumb
  //
  //       0: e59f2008  ldr r2, [pc, #8]  ; 10 <0x10>
  //       4: e3510001  cmp r1, #1
  //       8: 01a00002  moveq r0, r2
  //       c: e1a0f00e  mov pc, lr
  //      10: ca4227c5  .word 0xca4227c5

  if (enc.rn == kPCRegNum) {
    disp = disp + 8;
  }

  // Not Indexing
  if (!is_index) {
    AddAddrRegOp(inst, kIntRegName[enc.rn], kMemSize, kMemAction, pc_adjust);
  } else {
    AddAddrRegOp(inst, kIntRegName[enc.rn], kMemSize, kMemAction,
                 disp + pc_adjust);
  }

  AddIntRegOp(inst, enc.rt, 32, kRegAction);

  // Pre or Post Indexing
  if (write_back) {
    AddIntRegOp(inst, enc.rn, 32, Operand::kActionWrite);
    AddAddrRegOp(inst, kIntRegName[enc.rn], 32, Operand::kActionRead,
                 disp + pc_adjust);
  }

  // NOTE(akshayk): Instruction updating PC register will be a branching
  //                instruction. A branching instruction(conditional/
  //                unconditional) may update PC and invalidates `next_pc`.
  //                The semantics for these instructions take `next_pc` as
  //                arguments and should update it accordingly.

  if (enc.rt == kPCRegNum) {
    AddAddrRegOp(inst, kNextPCVariableName.data(), kAddressSize,
                 Operand::kActionWrite, 0);

    // NOTE(akshayk): A function can return by poping LR register to PC. Decoder
    //                having single view of instruction can't identify the register
    //                pushed on to the stack. All pop involving PC is categorized
    //                as function return
    //
    //           e.g: push {r2, lr}; ....; pop {r2, pc}
    //
    //                These instructions are categorized as indirect jump and lifter
    //                will identify if the PC gets updated with the return address
    //
    if (is_cond) {
      inst.branch_not_taken_pc = inst.next_pc;
      inst.category = Instruction::kCategoryConditionalIndirectJump;
    } else {
      inst.category = Instruction::kCategoryIndirectJump;
    }
  } else {

    // Add operand to ignore any updates of the next pc if done by semantic
    AddAddrRegOp(inst, kIgnoreNextPCVariableName.data(), kAddressSize,
                 Operand::kActionWrite, 0);
    inst.category = Instruction::kCategoryNormal;
  }
  return true;
}

// P o2  W o1
// 0  0  0  0 STR (register) — post-indexed if m == 15 wback && (n == 15 || n == t) then UNPREDICTABLE;
// 0  0  0  1 LDR (register) — post-indexed
// 0  0  1  0 STRT if n == 15 || n == t || m == 15 then UNPREDICTABLE;
// 0  0  1  1 LDRT
// 0  1  0  0 STRB (register) — post-indexed if t == 15 || m == 15 wback && (n == 15 || n == t) then UNPREDICTABLE;
// 0  1  0  1 LDRB (register) — post-indexed
// 0  1  1  0 STRBT if t == 15 || n == 15 || n == t then UNPREDICTABLE;
// 0  1  1  1 LDRBT
// 1  0     0 STR (register) — pre-indexed if m == 15 wback && (n == 15 || n == t) then UNPREDICTABLE;
// 1  0     1 LDR (register) — pre-indexed
// 1  1     0 STRB (register) — pre-indexed if t == 15 || m == 15 wback && (n == 15 || n == t) then UNPREDICTABLE;
// 1  1     1 LDRB (register) — pre-indexed
// Offset (P == 1 && W == 0):       LDR{<c>}{<q>} <Rt>, [<Rn>, {+/-}<Rm>{, <shift>}]
// Post-indexed (P == 0 && W == 0): LDR{<c>}{<q>} <Rt>, [<Rn>], {+/-}<Rm>{, <shift>}
// Pre-indexed (P == 1 && W == 1):  LDR{<c>}{<q>} <Rt>, [<Rn>, {+/-}<Rm>{, <shift>}]!
// Load/Store Word, Unsigned Byte (register)
template <Operand::Action kMemAction, Operand::Action kRegAction,
          unsigned kMemSize, bool kAlignPC = false>
static bool TryDecodeLoadStoreWordUBReg(Instruction &inst, uint32_t bits) {
  const LoadStoreWUBR enc = {bits};
  bool write_back = (!enc.P || enc.W);

  // if wback && (n == 15 || n == t) then UNPREDICTABLE;
  if ((write_back && (enc.rn == kPCRegNum || enc.rn == enc.rt)) ||
      (enc.rm == kPCRegNum && (enc.P || !enc.o2 || !enc.W)) ||
      (enc.rt == kPCRegNum && enc.o2)) {
    inst.category = Instruction::kCategoryError;
    return false;
  }

  inst.function = kLoadSWUB[enc.P << 3u | enc.W << 2u | enc.o2 << 1u | enc.o1];
  auto is_cond = DecodeCondition(inst, enc.cond);
  bool is_add = enc.u;
  bool is_index = enc.P;

  // LDR & LDRB (literal) are pc relative. Need to align the PC to the next nearest 4 bytes
  int64_t pc_adjust = 0;
  if (kAlignPC && enc.rn == kPCRegNum) {
    pc_adjust =
        static_cast<int32_t>(inst.pc & ~(3u)) - static_cast<int32_t>(inst.pc);
  }

  AddShiftRegImmOperand(inst, enc.rm, enc.type, enc.imm5, 0u, false);

  auto disp_expr = inst.operands.back().expr;
  auto disp_op = llvm::Instruction::Add;
  inst.operands.pop_back();
  if (!is_add) {
    disp_op = llvm::Instruction::Sub;
  }

  // Indexing
  if (!is_index) {
    AddAddrRegOp(inst, kIntRegName[enc.rn], kMemSize, kMemAction, pc_adjust);
  } else {
    AddAddrRegOp(inst, kIntRegName[enc.rn], kMemSize, kMemAction, pc_adjust);
    inst.operands.back().expr =
        inst.EmplaceBinaryOp(disp_op, inst.operands.back().expr, disp_expr);
  }

  AddIntRegOp(inst, enc.rt, 32, kRegAction);

  // Pre or Post Indexing
  if (write_back) {
    AddIntRegOp(inst, enc.rn, 32, Operand::kActionWrite);
    AddAddrRegOp(inst, kIntRegName[enc.rn], 32, Operand::kActionRead,
                 pc_adjust);
    inst.operands.back().expr =
        inst.EmplaceBinaryOp(disp_op, inst.operands.back().expr, disp_expr);
  }

  // NOTE(akshayk): Instruction updating PC register will be a branching
  //                instruction. A branching instruction(conditional/
  //                unconditional) may update PC and invalidates `next_pc`.
  //                The semantics for these instructions take `next_pc` as
  //                arguments and should update it accordingly.

  if (enc.rt == kPCRegNum) {
    AddAddrRegOp(inst, kNextPCVariableName.data(), kAddressSize,
                 Operand::kActionWrite, 0);

    // NOTE(akshayk): A function can return by poping LR register to PC. Decoder
    //                having single view of instruction can't identify the register
    //                pushed on to the stack. All pop involving PC is categorized
    //                as function return
    //
    //           e.g: push {r2, lr}; ....; pop {r2, pc}
    //
    //                These instructions are categorized as indirect jump and lifter
    //                will identify if the PC gets updated with the return address
    //
    if (is_cond) {
      inst.branch_not_taken_pc = inst.next_pc;
      inst.category = Instruction::kCategoryConditionalIndirectJump;
    } else {
      inst.category = Instruction::kCategoryIndirectJump;
    }
  } else {

    // Add operand to ignore any updates of the next pc if done by semantic
    AddAddrRegOp(inst, kIgnoreNextPCVariableName.data(), kAddressSize,
                 Operand::kActionWrite, 0);
    inst.category = Instruction::kCategoryNormal;
  }
  return true;
}

// op2 != 00 for extra load store instructions
// (see: Data-processing and miscellaneous instructions & Extra load/store)
static const char *const kLoadStoreDHSB[] = {
    [0b00010] = "LDRDp", [0b00001] = "STRHp",  [0b00011] = "STRDp",
    [0b00101] = "LDRHp", [0b00110] = "LDRSBp", [0b00111] = "LDRSHp",
    [0b01010] = nullptr, [0b01001] = "STRHT",  [0b01011] = nullptr,
    [0b01101] = "LDRHT", [0b01110] = "LDRSBT", [0b01111] = "LDRSHT",
    [0b10010] = "LDRD",  [0b10001] = "STRH",   [0b10011] = "STRD",
    [0b10101] = "LDRH",  [0b10110] = "LDRSB",  [0b10111] = "LDRSH",
    [0b11010] = "LDRDp", [0b11001] = "STRHp",  [0b11011] = "STRDp",
    [0b11101] = "LDRHp", [0b11110] = "LDRSBp", [0b11111] = "LDRSHp",
};

// P:W  o1   Rn    op2
//      0  1111   10  LDRD (literal)                   if Rt<0> == '1' t2 == 15 || wback then UNPREDICTABLE;
//           Note(sonya): For LDRD (literal), <Rt> is the first general-purpose register to be transferred, encoded
//           in the "Rt" field. This register must be even-numbered and not R14.
// != 01 1  1111   01  LDRH (literal)                   if t == 15 || wback then UNPREDICTABLE;
// != 01 1  1111   10  LDRSB (literal)                  if t == 15 || wback then UNPREDICTABLE;
// != 01 1  1111   11  LDRSH (literal)                  if t == 15 || wback then UNPREDICTABLE;
// 00   0 != 1111 10  LDRD (immediate) — post-indexed  if t2 == 15   wback && (n == t || n == t2) then UNPREDICTABLE; if Rt<0> == '1' then UNPREDICTABLE;
//           Note(sonya): For LDRD (immediate), <Rt> is the first general-purpose register to be transferred, encoded
//           in the "Rt" field. This register must be even-numbered and not R14.
// 00   0         01  STRH (immediate) — post-indexed  if t == 15    wback && (n == 15 || n == t) then UNPREDICTABLE;
// 00   0         11  STRD (immediate) — post-indexed  if t2 == 15   wback && (n == 15 || n == t || n == t2) then UNPREDICTABLE; (t != 15)
// 00   1 != 1111 01  LDRH (immediate) — post-indexed  if t == 15    wback && (n == 15 || n == t) then UNPREDICTABLE;
// 00   1 != 1111 10  LDRSB (immediate) — post-indexed if t == 15    wback && (n == 15 || n == t) then UNPREDICTABLE;
// 00   1 != 1111 11  LDRSH (immediate) — post-indexed if t == 15    wback && (n == 15 || n == t) then UNPREDICTABLE;
// 01   0 != 1111 10  UNALLOCATED
// 01   0         01  STRHT                            if t == 15 || n == 15 || n == t then UNPREDICTABLE;
// 01   0         11  UNALLOCATED
// 01   1         01  LDRHT                            if t == 15 || n == 15 || n == t then UNPREDICTABLE;
// 01   1         10  LDRSBT                           if t == 15 || n == 15 || n == t then UNPREDICTABLE;
// 01   1         11  LDRSHT                           if t == 15 || n == 15 || n == t then UNPREDICTABLE;
// 10   0 != 1111 10  LDRD (immediate) — offset        if t2 == 15   wback && (n == t || n == t2) then UNPREDICTABLE; if Rt<0> == '1' then UNPREDICTABLE;
//           Note(sonya): For LDRD (immediate), <Rt> is the first general-purpose register to be transferred, encoded
//           in the "Rt" field. This register must be even-numbered and not R14.
// 10   0         01  STRH (immediate) — offset        if t == 15    wback && (n == 15 || n == t) then UNPREDICTABLE;
// 10   0         11  STRD (immediate) — offset        if t2 == 15   wback && (n == 15 || n == t || n == t2) then UNPREDICTABLE; (t != 15)
// 10   1 != 1111 01  LDRH (immediate) — offset        if t == 15    wback && n == t then UNPREDICTABLE;
// 10   1 != 1111 10  LDRSB (immediate) — offset       if t == 15    wback && n == t then UNPREDICTABLE;
// 10   1 != 1111 11  LDRSH (immediate) — offset       if t == 15    wback && n == t then UNPREDICTABLE;
// 11   0 != 1111 10  LDRD (immediate) — pre-indexed   if t2 == 15   wback && (n == t || n == t2) then UNPREDICTABLE; if Rt<0> == '1' then UNPREDICTABLE;
//           Note(sonya): For LDRD (immediate), <Rt> is the first general-purpose register to be transferred, encoded
//           in the "Rt" field. This register must be even-numbered and not R14.
// 11   0         01  STRH (immediate) — pre-indexed   if t == 15    wback && (n == 15 || n == t) then UNPREDICTABLE;
// 11   0         11  STRD (immediate) — pre-indexed   if t2 == 15   wback && (n == 15 || n == t || n == t2) then UNPREDICTABLE; (t != 15)
// 11   1 != 1111 01  LDRH (immediate) — pre-indexed   if t == 15    wback && n == t then UNPREDICTABLE;
// 11   1 != 1111 10  LDRSB (immediate) — pre-indexed  if t == 15    wback && n == t then UNPREDICTABLE;
// 11   1 != 1111 11  LDRSH (immediate) — pre-indexed  if t == 15    wback && n == t then UNPREDICTABLE;
// Load/Store Dual, Half, Signed Byte (immediate, literal)
template <Operand::Action kMemAction, Operand::Action kRegAction,
          unsigned kMemSize, bool kAlignPC = false>
static bool TryDecodeLoadStoreDualHalfSignedBIL(Instruction &inst,
                                                uint32_t bits) {
  const LoadStoreDualHSBIL enc = {bits};
  auto instruction =
      kLoadStoreDHSB[enc.P << 4 | enc.W << 3 | enc.o1 << 2 | enc.op2];

  if (enc.rn == kPCRegNum && !instruction && enc.op2 == 0b10) {
    // LDRD (literal), LDRH (literal), LDRSB (literal), LDRSH (literal)
//    if (enc.rt & 0b1) {
//      // Catches if Rt<0> == '1' then UNPREDICTABLE;
//      inst.category = Instruction::kCategoryError;
//      return false;
//    }
    inst.function = "LDRDp";
  } else if (instruction) {
    inst.function = instruction;
  } else {
    inst.category = Instruction::kCategoryError;
    return false;
  }

  // write_back: All insts but LDRD, STRH, STRD, LDRH, LDRSB, LDRSH (immediate) — offset
  bool write_back = (!enc.P || enc.W);

  bool is_add = enc.U;
  bool is_index = enc.P;

  // is_dual: LDRD (literal and immediate) && STRD (immediate)
  bool is_dual = !enc.o1 && enc.op2 >> 1;

  uint32_t rt2 = enc.rt + 1;

  if (
      // rt != 15 for any instruction
      (enc.rt == kPCRegNum) ||
      // rt must be even && rt != 14 for all LDRD insts
      (!enc.o1 && (enc.op2 == 0b10) && ((enc.rt & 0b1) || enc.rt != kLRRegNum)) ||
      // t2 != 15 for all dual instructions
      (is_dual && rt2 == kPCRegNum) ||
      // if wback && (n == t  || n == t2) then UNPREDICTABLE; (LDRD)
      // if wback && (n == 15 || n == t ) then UNPREDICTABLE; (STRH && LDRH)
      // if wback && (n == 15 || n == t || n == t2) then UNPREDICTABLE; (STRD)
      (write_back && (enc.rn == kPCRegNum || enc.rn == enc.rt || (is_dual && enc.rn == rt2)))) {
    inst.category = Instruction::kCategoryError;
    return false;
  }
  auto is_cond = DecodeCondition(inst, enc.cond);

  // LDR & LDRB (literal) are pc relative. Need to align the PC to the next nearest 4 bytes
  int64_t pc_adjust = 0;
  if (kAlignPC && enc.rn == kPCRegNum) {
    pc_adjust =
        static_cast<int32_t>(inst.pc & ~(3u)) - static_cast<int32_t>(inst.pc);
  }

  auto disp = static_cast<int64_t>(enc.imm4H << 4 | enc.imm4L);

  // Subtract
  if (!is_add) {
    disp = -disp;
  }

  // Not Indexing
  if (!is_index) {
    AddAddrRegOp(inst, kIntRegName[enc.rn], kMemSize, kMemAction, pc_adjust);
  } else {
    AddAddrRegOp(inst, kIntRegName[enc.rn], kMemSize, kMemAction,
                 disp + pc_adjust);
  }

  AddIntRegOp(inst, enc.rt, 32, kRegAction);

  // Add t2 =  t + 1 reg for dual instructions
  if (is_dual) {
    AddIntRegOp(inst, enc.rt + 1, 32, kRegAction);
  }

  // Pre or Post Indexing
  if (write_back) {
    AddIntRegOp(inst, enc.rn, 32, Operand::kActionWrite);
    AddAddrRegOp(inst, kIntRegName[enc.rn], 32, Operand::kActionRead,
                 disp + pc_adjust);
  }

  // NOTE(akshayk): Instruction updating PC register will be a branching
  //                instruction. A branching instruction(conditional/
  //                unconditional) may update PC and invalidates `next_pc`.
  //                The semantics for these instructions take `next_pc` as
  //                arguments and should update it accordingly.

  if (enc.rt == kPCRegNum) {
    AddAddrRegOp(inst, kNextPCVariableName.data(), kAddressSize,
                 Operand::kActionWrite, 0);

    // NOTE(akshayk): A function can return by poping LR register to PC. Decoder
    //                having single view of instruction can't identify the register
    //                pushed on to the stack. All pop involving PC is categorized
    //                as function return
    //
    //           e.g: push {r2, lr}; ....; pop {r2, pc}
    //
    //                These instructions are categorized as indirect jump and lifter
    //                will identify if the PC gets updated with the return address
    //

    if (is_cond) {
      inst.branch_not_taken_pc = inst.next_pc;
      inst.category = Instruction::kCategoryConditionalIndirectJump;
    } else {
      inst.category = Instruction::kCategoryIndirectJump;
    }
  } else {

    // Add operand to ignore any updates of the next pc if done by semantic
    AddAddrRegOp(inst, kIgnoreNextPCVariableName.data(), kAddressSize,
                 Operand::kActionWrite, 0);
    inst.category = Instruction::kCategoryNormal;
  }
  return true;
}

// P W o1  op2
// 0 0  0   01  STRH (register) — post-indexed  if t == 15 || m == 15  wback && (n == 15 || n == t) then UNPREDICTABLE;
// 0 0  0   10  LDRD (register) — post-indexed  if t2 == 15 || m == 15 || m == t || m == t2 wback && (n == 15 || n == t || n == t2) then UNPREDICTABLE; if Rt<0> == '1' then UNPREDICTABLE;
// 0 0  0   11  STRD (register) — post-indexed  if t2 == 15 || m == 15 wback && (n == 15 || n == t || n == t2) then UNPREDICTABLE; if Rt<0> == '1' then UNPREDICTABLE;
//           Note(sonya): For LDRD (register) and STRD (register), <Rt> Is the first general-purpose register to be transferred,
//             encoded in the "Rt" field. This register must be even-numbered and not R14. If Rt == 15 then CONSTRAINED UNPREDICTABLE behavior occurs.
// 0 0  1   01  LDRH (register) — post-indexed  if t == 15 || m == 15 wback && (n == 15 || n == t) then UNPREDICTABLE;
// 0 0  1   10  LDRSB (register) — post-indexed if t == 15 || m == 15 wback && (n == 15 || n == t) then UNPREDICTABLE;
// 0 0  1   11  LDRSH (register) — post-indexed if t == 15 || m == 15 wback && (n == 15 || n == t) then UNPREDICTABLE
// 0 1  0   01  STRHT                           if t == 15 || n == 15 || n == t || m == 15 then UNPREDICTABLE;
// 0 1  0   10  UNALLOCATED
// 0 1  0   11  UNALLOCATED
// 0 1  1   01  LDRHT                           if t == 15 || n == 15 || n == t || m == 15 then UNPREDICTABLE;
// 0 1  1   10  LDRSBT                          if t == 15 || n == 15 || n == t || m == 15 then UNPREDICTABLE;
// 0 1  1   11  LDRSHT                          if t == 15 || n == 15 || n == t || m == 15 then UNPREDICTABLE;
// 1    0   01  STRH (register) — pre-indexed   if t == 15 || m == 15  wback && (n == 15 || n == t) then UNPREDICTABLE;
// 1    0   10  LDRD (register) — pre-indexed   if t2 == 15 || m == 15 || m == t || m == t2 wback && (n == 15 || n == t || n == t2) then UNPREDICTABLE; if Rt<0> == '1' then UNPREDICTABLE;
// 1    0   11  STRD (register) — pre-indexed   if t2 == 15 || m == 15 wback && (n == 15 || n == t || n == t2) then UNPREDICTABLE; if Rt<0> == '1' then UNPREDICTABLE;
//           Note(sonya): For LDRD (register) and STRD (register), <Rt> Is the first general-purpose register to be transferred,
//             encoded in the "Rt" field. This register must be even-numbered and not R14. If Rt == 15 then CONSTRAINED UNPREDICTABLE behavior occurs.
// 1    1   01  LDRH (register) — pre-indexed   if t == 15 || m == 15  wback && (n == 15 || n == t) then UNPREDICTABLE;
// 1    1   10  LDRSB (register) — pre-indexed  if t == 15 || m == 15 wback && (n == 15 || n == t) then UNPREDICTABLE;
// 1    1   11  LDRSH (register) — pre-indexed  if t == 15 || m == 15 wback && (n == 15 || n == t) then UNPREDICTABLE
// Load/Store Dual, Half, Signed Byte (register)
template <Operand::Action kMemAction, Operand::Action kRegAction,
          unsigned kMemSize, bool kAlignPC = false>
static bool TryDecodeLoadStoreDualHalfSignedBReg(Instruction &inst,
                                                 uint32_t bits) {
  const LoadStoreDualHSBR enc = {bits};
  auto instruction =
      kLoadStoreDHSB[enc.P << 4 | enc.W << 3 | enc.o1 << 2 | enc.op2];

  bool write_back = (!enc.P || enc.W);
  bool is_add = enc.U;
  bool is_index = enc.P;
  bool is_dual = !enc.o1 && enc.op2 >> 1;
  bool is_unpriv = enc.W && !enc.P;
  uint32_t rt2 = enc.rt + 1;

  if (
      // UNALLOCATED instruction
      !instruction ||

      // Rt cannot be 15 for any instruction except STRDp as a special exception
      (enc.rt == kPCRegNum && !(!enc.o1 && enc.op2 == 0b11u)) ||

      // all dual insts (except STRDp) must be even and not the link register
      (is_dual && (((enc.rt & 0b1)) || enc.rt == kLRRegNum) && !(!enc.o1 && enc.op2 == 0b11u) ) ||

      // for STRDp rt can be r15 or must be even and not LR
      ((!enc.o1 && enc.op2 == 0b11u) && (((enc.rt & 0b1) && enc.rt != kPCRegNum) ||  enc.rt == kLRRegNum))||

      (write_back && (enc.rn == kPCRegNum || enc.rn == enc.rt ||
          (is_dual && enc.rn == rt2) || (is_unpriv && enc.rm == kPCRegNum))) ||
      (is_dual && (enc.rt == kLRRegNum || enc.rm == kPCRegNum ||
          (enc.op2 == 0b10 && (enc.rm == enc.rt || enc.rm == rt2))))
      ) {
    inst.category = Instruction::kCategoryError;
    return false;
  } else {
    inst.function = instruction;
  }

  // CONSTRAINED UNPREDICTABLE behavior for STRD (register):
  //
  //   If Rt<0> == '1', then one of the following behaviors must occur:
  //     - The instruction is undefined.
  //     - The instruction executes as NOP.
  //     - The instruction executes with the additional decode: t<0> = '0'.
  //     - The instruction executes with the additional decode: t2 = t.
  //     - The instruction executes as described, with no change to its behavior
  //      and no additional side-effects. This does not apply when Rt == '1111'.
  //
  //   If t == 15 || t2 == 15, then one of the following behaviors must occur:
  //     - The instruction is undefined.
  //     - The instruction executes as NOP.
  //     - The store instruction performs the store using the specified
  //      addressing mode but the value corresponding to R15 is unknown.
  //
  // Permitted UNPREDICTABLE behavior for STRDp only when rt is r15 only
  if (enc.rt == kPCRegNum) {
    // The instruction executes with the additional decode: t2 = t.
    CHECK(!enc.o1 && enc.op2 == 0b11u)
              << "Rt is R15 for an instruction other than STRDp!!";
    rt2 = enc.rt;
  }

  auto is_cond = DecodeCondition(inst, enc.cond);

  // LDR & LDRB (literal) are pc relative. Need to align the PC to the next nearest 4 bytes
  int64_t pc_adjust = 0;
  if (kAlignPC && enc.rn == kPCRegNum) {
    pc_adjust =
        static_cast<int32_t>(inst.pc & ~(3u)) - static_cast<int32_t>(inst.pc);
  }

  // Note: AArch32 has shift_size = 0 and type = LSL so disp is an unshifted reg
  // Thumb instructions have shift
  AddIntRegOp(inst, enc.rm, 32, Operand::kActionRead);
  auto disp_expr = inst.operands.back().expr;
  auto disp_op = llvm::Instruction::Add;
  inst.operands.pop_back();

  if (!is_add) {
    disp_op = llvm::Instruction::Sub;
  }

  // Not Indexing
  if (!is_index) {
    AddAddrRegOp(inst, kIntRegName[enc.rn], kMemSize, kMemAction, pc_adjust);
  } else {
    AddAddrRegOp(inst, kIntRegName[enc.rn], kMemSize, kMemAction, pc_adjust);
    inst.operands.back().expr =
        inst.EmplaceBinaryOp(disp_op, inst.operands.back().expr, disp_expr);
  }

  AddIntRegOp(inst, enc.rt, 32, kRegAction);

  if (is_dual) {
    AddIntRegOp(inst, rt2, 32, kRegAction);
  }

  // Pre or Post Indexing
  if (write_back) {
    AddIntRegOp(inst, enc.rn, 32, Operand::kActionWrite);
    AddAddrRegOp(inst, kIntRegName[enc.rn], 32, Operand::kActionRead,
                 pc_adjust);
    inst.operands.back().expr =
        inst.EmplaceBinaryOp(disp_op, inst.operands.back().expr, disp_expr);
  }

  // NOTE(akshayk): Instruction updating PC register will be a branching
  //                instruction. A branching instruction(conditional/
  //                unconditional) may update PC and invalidates `next_pc`.
  //                The semantics for these instructions take `next_pc` as
  //                arguments and should update it accordingly.

  if (enc.rt == kPCRegNum && kRegAction == Operand::Action::kActionWrite) {
    AddAddrRegOp(inst, kNextPCVariableName.data(), kAddressSize,
                 Operand::kActionWrite, 0);

    if (is_cond) {
      inst.branch_not_taken_pc = inst.next_pc;
      inst.category = Instruction::kCategoryConditionalIndirectJump;
    } else {
      inst.category = Instruction::kCategoryIndirectJump;
    }
  } else {

    // Add operand to ignore any updates of the next pc if done by semantic
    AddAddrRegOp(inst, kIgnoreNextPCVariableName.data(), kAddressSize,
                 Operand::kActionWrite, 0);
    inst.category = Instruction::kCategoryNormal;
  }
  return true;
}

// P  U op  L  register_list
// 0  0  0  0                    STMDA, STMED if n == 15 || BitCount(registers) < 1 then UNPREDICTABLE; if i == n && wback && i != LowestSetBit(registers) then bits(32) UNKNOWN;
// 0  0  0  1                    LDMDA, LDMFA if n == 15 || BitCount(registers) < 1 then UNPREDICTABLE; if wback && registers<n> == '1' then UNPREDICTABLE;
// 0  1  0  0                    STM, STMIA, STMEA if n == 15 || BitCount(registers) < 1 then UNPREDICTABLE; if i == n && wback && i != LowestSetBit(registers) then bits(32) UNKNOWN;
// 0  1  0  1                    LDM, LDMIA, LDMFD if n == 15 || BitCount(registers) < 1 then UNPREDICTABLE; if wback && registers<n> == '1' then UNPREDICTABLE;
//       1  0                    STM (User registers) if n == 15 || BitCount(registers) < 1 then UNPREDICTABLE;
// 1  0  0  0                    STMDB, STMFD if n == 15 || BitCount(registers) < 1 then UNPREDICTABLE; if i == n && wback && i != LowestSetBit(registers) then bits(32) UNKNOWN;
// 1  0  0  1                    LDMDB, LDMEA if n == 15 || BitCount(registers) < 1 then UNPREDICTABLE; if wback && registers<n> == '1' then UNPREDICTABLE;
//       1  1  0xxxxxxxxxxxxxxx  LDM (User registers) if n == 15 || BitCount(registers) < 1 then UNPREDICTABLE;
// 1  1  0  0                    STMIB, STMFA if n == 15 || BitCount(registers) < 1 then UNPREDICTABLE; if i == n && wback && i != LowestSetBit(registers) then bits(32) UNKNOWN;
// 1  1  0  1                    LDMIB, LDMED if n == 15 || BitCount(registers) < 1 then UNPREDICTABLE; if wback && registers<n> == '1' then UNPREDICTABLE;
//       1  1  1xxxxxxxxxxxxxxx  LDM (exception return) if n == 15 then UNPREDICTABLE; if wback && registers<n> == '1' then UNPREDICTABLE;
static const char *const kLoadStoreM[] = {
    [0b0000] = "STMDA", [0b0001] = "LDMDA",
    [0b0010] = "STMu",  // (User registers)
    [0b0011] = "LDM",  // (User registers) || (exception return)
    [0b0100] = "STM",   [0b0101] = "LDM",
    [0b0110] = "STMu",  // (User registers)
    [0b0111] = "LDM",  // (User registers) || (exception return)
    [0b1000] = "STMDB", [0b1001] = "LDMDB",
    [0b1010] = "STMu",  // (User registers)
    [0b1011] = "LDM",  // (User registers) || (exception return)
    [0b1100] = "STMIB", [0b1101] = "LDMIB",
    [0b1110] = "STMu",  // (User registers)
    [0b1111] = "LDM",  // (User registers) || (exception return)
};

// Load/Store Multiple
// Note that:
// LDM{<c>}{<q>} SP!, <registers> is an alias for POP{<c>}{<q>} <registers>
// STMDB{<c>}{<q>} SP!, <registers> is an alias for PUSH{<c>}{<q>} <registers>
template <Operand::Action kMemAction, Operand::Action kRegAction,
          bool kAlignPC = false>
static bool TryDecodeLoadStoreMultiple(Instruction &inst, uint32_t bits) {
  const LoadStoreM enc = {bits};
  inst.function = kLoadStoreM[enc.P << 3 | enc.U << 2 | enc.op << 1 | enc.L];

  if (enc.op && enc.L && (enc.register_list >> 15)) {

    // Exception Return
    inst.function += "e";
  } else if (enc.op && enc.L) {

    // User registers
    inst.function += "u";
  }

  auto wback = enc.W;
  uint32_t reg_cnt = 0;
  for (uint32_t i = 0; 16u > i; i++) {
    if ((0b1 << i) & enc.register_list) {
      if (wback && i == enc.rn && ((!reg_cnt && !enc.L) || enc.L)) {

        // if i == n && wback && i != LowestSetBit(registers) then bits(32) UNKNOWN;
        inst.category = Instruction::kCategoryError;
        return false;
      }
      reg_cnt++;
    }
  }

  if (enc.rn == 15 || (reg_cnt < 1u)) {
    inst.category = Instruction::kCategoryError;
    return false;
  }

  auto is_cond = DecodeCondition(inst, enc.cond);

  uint32_t wback_disp = 0;
  uint32_t disp = 0;
  switch (enc.P << 2 | enc.U << 1 | enc.op) {
    case 0b000:
      if (wback) {
        wback_disp = -4 * reg_cnt;
      }
      disp = -4 * reg_cnt + 4;
      break;
    case 0b010:
      if (wback) {
        wback_disp = 4 * reg_cnt;
      }
      // disp remains 0
      break;
    case 0b100:
      if (wback) {
        wback_disp = -4 * reg_cnt;
      }
      disp = -4 * reg_cnt;
      break;
    case 0b110:
      if (wback) {
        wback_disp = 4 * reg_cnt;
      }
      disp = 4;
      break;

      // TODO(Sonya): STM (User registers), LDM (User registers), LDM (exception return)
  }

  AddImmOp(inst, enc.register_list, 16u, false);
  AddIntRegOp(inst, enc.rn, 32u, Operand::kActionWrite);
  AddAddrRegOp(inst, kIntRegName[enc.rn], 32u, kMemAction, wback_disp);
  AddAddrRegOp(inst, kIntRegName[enc.rn], 32u, kMemAction, disp);
  for (uint32_t i = 0u; 16u > i; i++) {
    AddIntRegOp(inst, i, 32u, kRegAction);
  }

  // NOTE(akshayk): `POP` instruction updating PC can move link register
  //                to program counter and be alias to the return. These
  //                instructions should be categorized as function return.
  //          e.g :
  //                0: e92d4004  push {r2, lr}
  //                   ...
  //               10: e8bd8004  pop  {r2, pc}
  //
  //                LR can also be moved(pop'd) to PC indirectly using
  //                one of scratch register. All POP updating PC is
  //                considered function return and lifting work-list will
  //                take care of identifying if its indirect jump
  //

  if (enc.register_list & (0b1 << 15u)) {
    AddAddrRegOp(inst, kNextPCVariableName.data(), kAddressSize,
                 Operand::kActionWrite, 0);

    if (is_cond) {
      inst.branch_not_taken_pc = inst.next_pc;
      inst.category = Instruction::kCategoryConditionalIndirectJump;
    } else {
      inst.category = Instruction::kCategoryIndirectJump;
    }
  } else {

    // Add operand to ignore any updates of the next pc if done by semantic
    AddAddrRegOp(inst, kIgnoreNextPCVariableName.data(), kAddressSize,
                 Operand::kActionWrite, 0);
    inst.category = Instruction::kCategoryNormal;
  }
  return true;
}


// Index from: op1 | Ra == 15 | op2
static const char *kSpecial(uint32_t index) {
  if (index >> 8) {
    return nullptr;  // TODO(Sonya) MSR (immediate)
  }
  switch (index) {
    case 0b000000000: return "NOP";
    case 0b000000001:

      // TODO(Sonya) return "YIELD";
    case 0b000000010:

      // TODO(Sonya) return "WFE";
    case 0b000000011:

      // TODO(Sonya) return "WFI";
    case 0b000000100:

      // TODO(Sonya) return "SEV";
    case 0b000000101:

      // TODO(Sonya) return "SEVL";
      return nullptr;
    case 0b000000110:
    case 0b000000111: return "HINT_1";  // Reserved hint, behaves as NOP
    case 0b000001000:
    case 0b000001001:
    case 0b000001010:
    case 0b000001011:
    case 0b000001100:
    case 0b000001101:
    case 0b000001110:
    case 0b000001111:
      return "HINT_2";  // Reserved hint, behaves as NOP

    // case 0b000010000: return "ESB"; // ARMv8.2
    case 0b000010001: return "HINT_3";  // Reserved hint, behaves as NOP
    case 0b000010010:
    case 0b000010011: return "HINT_4";  // Reserved hint, behaves as NOP
    case 0b000010100:
    case 0b000010101:
    case 0b000010110:
    case 0b000010111: return "HINT_5";  // Reserved hint, behaves as NOP
    case 0b000011000:
    case 0b000011001:
    case 0b000011010:
    case 0b000011011:
    case 0b000011100:
    case 0b000011101:
    case 0b000011110:
    case 0b000011111: return "HINT_6";  // Reserved hint, behaves as NOP
    case 0b011100000:
    case 0b011100001:
    case 0b011100010:
    case 0b011100011:
    case 0b011100100:
    case 0b011100101:
    case 0b011100110:
    case 0b011100111:
    case 0b011101000:
    case 0b011101001:
    case 0b011101010:
    case 0b011101011:
    case 0b011101100:
    case 0b011101101:
    case 0b011101110:
    case 0b011101111: return "HINT_11";  // Reserved hint, behaves as NOP
  }
  switch (index >> 5) {
    case 0b0001: return "HINT_7";  // Reserved hint, behaves as NOP
    case 0b0010:
    case 0b0011: return "HINT_8";  // Reserved hint, behaves as NOP
    case 0b0100:
    case 0b0101: return "HINT_9";  // Reserved hint, behaves as NOP
    case 0b0110: return "HINT_10";  // Reserved hint, behaves as NOP
    default: return nullptr;
  }
}

// R:imm4         imm12
// != 00000                MSR (immediate)
// 00000     xxxx00000000  NOP
// 00000     xxxx00000001  YIELD
// 00000     xxxx00000010  WFE
// 00000     xxxx00000011  WFI
// 00000     xxxx00000100  SEV
// 00000     xxxx00000101  SEVL
// 00000     xxxx0000011x  Reserved hint, behaves as NOP
// 00000     xxxx00001xxx  Reserved hint, behaves as NOP
// 00000     xxxx00010000  ESB ARMv8.2
// 00000     xxxx00010001  Reserved hint, behaves as NOP
// 00000     xxxx0001001x  Reserved hint, behaves as NOP
// 00000     xxxx000101xx  Reserved hint, behaves as NOP
// 00000     xxxx00011xxx  Reserved hint, behaves as NOP
// 00000     xxxx001xxxxx  Reserved hint, behaves as NOP
// 00000     xxxx01xxxxxx  Reserved hint, behaves as NOP
// 00000     xxxx10xxxxxx  Reserved hint, behaves as NOP
// 00000     xxxx110xxxxx  Reserved hint, behaves as NOP
// 00000     xxxx1110xxxx  Reserved hint, behaves as NOP
// 00000     xxxx1111xxxx  DBG
// Move Special Register and Hints (immediate)
// TODO(Sonya): This literally only has functionality for NOP and "behaves as NOP"
static bool TryMoveSpecialRegisterAndHintsI(Instruction &inst, uint32_t bits) {
  const SpecialRegsAndHints enc = {bits};

  // (R:imm4 != 00000)<1 bit>:imm12<low 8 bits only>
  auto instruction =
      kSpecial(((enc.R << 4 | enc.imm4) != 0b0u) << 8 | (enc.imm12 & 255u));
  if (!instruction) {
    inst.category = Instruction::kCategoryError;
    return false;
  }

  if (strstr(instruction, "NOP") || strstr(instruction, "HINT")) {
    inst.category = Instruction::kCategoryNoOp;
  } else {
    inst.category = Instruction::kCategoryNormal;
  }

  // A NOP is still conditional:
  //  if ConditionPassed() then
  //      EncodingSpecificOperations();
  //      // Do nothing
  inst.function = instruction;
  DecodeCondition(inst, enc.cond);
  return true;
}

// Can package semantics for MOV with ORR and MVN with BIC since src1 will be
// 0 and 1 for MOV and MVN respectively, mirroring the semantics in LOGICAL.cpp
static InstEval *kLogArithEvaluators[] = {
    [0b0] = +[](uint32_t src1,
                uint32_t src2) { return std::optional<uint32_t>(src1 | src2); },
    [0b1] =
        +[](uint32_t src1, uint32_t src2) {
          return std::optional<uint32_t>(src1 & ~src2);
        },
};

// 00  ORR, ORRS (register) -- rd, rn, & rm
// 01  MOV, MOVS (register) -- rd, & rm only
// 10  BIC, BICS (register) -- rd, rn, & rm
// 11  MVN, MVNS (register) -- rd, & rm only
static const char *const kLogicalArithmeticRRRI[] = {
    [0b000] = "ORRrr",  [0b001] = "ORRSrr", [0b010] = "MOVrr",
    [0b011] = "MOVSrr", [0b100] = "BICrr",  [0b101] = "BICSrr",
    [0b110] = "MVNrr",  [0b111] = "MVNSrr",
};

// Logical Arithmetic (three register, immediate shift)
static bool TryLogicalArithmeticRRRI(Instruction &inst, uint32_t bits) {
  const LogicalArithRRRI enc = {bits};

  inst.function = kLogicalArithmeticRRRI[enc.opc << 1u | enc.s];
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

  AddShiftRegImmOperand(inst, enc.rm, enc.type, enc.imm5, enc.s, true);

  return EvalPCDest(inst, enc.s, enc.rd, kLogArithEvaluators[enc.opc >> 1u],
                    is_cond);
}

// Logical Arithmetic (three register, register shift)
static bool TryLogicalArithmeticRRRR(Instruction &inst, uint32_t bits) {
  const LogicalArithRRRR enc = {bits};

  if (enc.rn == kPCRegNum || enc.rd == kPCRegNum || enc.rs == kPCRegNum ||
      enc.rm == kPCRegNum) {
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
  AddAddrRegOp(inst, kIgnoreNextPCVariableName.data(), kAddressSize,
               Operand::kActionWrite, 0);

  inst.category = Instruction::kCategoryNormal;
  return true;
}

// Logical Arithmetic (two register and immediate)
static bool TryLogicalArithmeticRRI(Instruction &inst, uint32_t bits) {
  const LogicalArithmeticRRI enc = {bits};

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
  return EvalPCDest(inst, enc.s, enc.rd, kLogArithEvaluators[enc.opc >> 1u],
                    is_cond);
}

// Move Halfword (immediate)
static bool TryDecodeMoveHalfword(Instruction &inst, uint32_t bits) {
  const MoveHW enc = {bits};

  // if d == 15 then UNPREDICTABLE;
  if (enc.rd == kPCRegNum) {
    inst.category = Instruction::kCategoryError;
    return false;
  } else if (enc.H) {
    inst.function = "MOVT";
  } else {
    inst.function = "MOVW";
  }

  DecodeCondition(inst, enc.cond);
  AddIntRegOp(inst, enc.rd, 32, Operand::kActionWrite);
  if (enc.H) {
    AddIntRegOp(inst, enc.rd, 32, Operand::kActionRead);
  }
  AddImmOp(inst, enc.imm4 << 12 | enc.imm12);
  if (!enc.H) {
    AddImmOp(inst, 0);

    // Add kIgnoreNextPCVariableName to allow MOVW to share semantics with ORR
    AddAddrRegOp(inst, kIgnoreNextPCVariableName.data(), kAddressSize,
                 Operand::kActionWrite, 0);
  }
  inst.category = Instruction::kCategoryNormal;
  return true;
}

// 00  TST (register)
// 01  TEQ (register)
// 10  CMP (register)
// 11  CMN (register)
static const char *const kIntegerTestAndCompareR[] = {
    [0b00] = "TSTr",
    [0b01] = "TEQr",
    [0b10] = "CMPr",
    [0b11] = "CMNr",
};

// Integer Test and Compare (two register, immediate shift)
static bool TryIntegerTestAndCompareRRI(Instruction &inst, uint32_t bits) {
  const IntTestCompRRI enc = {bits};

  auto instruction = kIntegerTestAndCompareR[enc.opc];

  inst.function = instruction;
  DecodeCondition(inst, enc.cond);

  AddIntRegOp(inst, enc.rn, 32, Operand::kActionRead);
  AddShiftRegImmOperand(inst, enc.rm, enc.type, enc.imm5, 1u, true);

  inst.category = Instruction::kCategoryNormal;
  return true;
}

// Integer Test and Compare (two register, register shift)
static bool TryIntegerTestAndCompareRRR(Instruction &inst, uint32_t bits) {
  const IntTestCompRRR enc = {bits};

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
  const IntTestCompRI enc = {bits};

  auto instruction = kIntegerTestAndCompareR[enc.opc];

  inst.function = instruction;
  DecodeCondition(inst, enc.cond);

  AddIntRegOp(inst, enc.rn, 32, Operand::kActionRead);
  ExpandTo32AddImmAddCarry(inst, enc.imm12, 1u);

  inst.category = Instruction::kCategoryNormal;
  return true;
}

// cond  H
// != 1111 0 B
// != 1111 1 BL, BLX (immediate) — A1
// 1111    BL, BLX (immediate) — A2
// Branch (immediate)
static bool TryBranchImm(Instruction &inst, uint32_t bits) {
  const BranchI enc = {bits};
  auto is_cond = DecodeCondition(inst, enc.cond);

  auto is_func = false;

  // PC used by the branch instruction is actually the address of the next instruction
  auto target_pc = static_cast<uint32_t>(inst.pc + 8 +
                                         static_cast<uint32_t>(enc.imm24 << 2));
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

  AddAddrRegOp(inst, kPCVariableName.data(), kAddressSize, Operand::kActionRead,
               offset);

  inst.branch_taken_pc = target_pc;
  inst.branch_not_taken_pc = inst.pc + 4;
  if (is_cond && is_func) {
    inst.category = Instruction::kCategoryConditionalDirectFunctionCall;
  } else if (is_cond) {
    inst.category = Instruction::kCategoryConditionalBranch;
  } else if (is_func) {
    inst.category = Instruction::kCategoryDirectFunctionCall;
  } else {
    inst.category = Instruction::kCategoryDirectJump;
  }
  AddAddrRegOp(inst, kNextPCVariableName.data(), kAddressSize,
               Operand::kActionRead, 0);

  Operand::Register reg;
  reg.size = kAddressSize;
  reg.name = remill::kNextPCVariableName;
  auto &next_pc = inst.EmplaceOperand(reg);
  next_pc.action = Operand::kActionWrite;

  if (is_func) {
    Operand::Register reg;
    reg.size = kAddressSize;
    reg.name = remill::kReturnPCVariableName;
    auto &next_pc = inst.EmplaceOperand(reg);
    next_pc.action = Operand::kActionWrite;
  }

  return true;
}

static const char *const kBX[] = {
    [0b01] = "BX",
    [0b10] = "BXJ",  // unsupported
    [0b11] = "BLX",
};

static bool TryDecodeBX(Instruction &inst, uint32_t bits) {
  const Misc enc = {bits};

  if (enc.op1 == 0b10) {  // BJX unsupported
    LOG(ERROR) << "BJX unsupported";
    inst.category = Instruction::kCategoryError;
    return false;
  } else if (enc.op1 == 0b11 && enc.Rm == kPCRegNum) {

    // if m == 15 then UNPREDICTABLE;
    inst.category = Instruction::kCategoryError;
    return false;
  }

  auto is_cond = DecodeCondition(inst, enc.cond);
  inst.function = kBX[enc.op1];
  if (is_cond) {
    inst.function += "COND";
  }

  AddAddrRegOp(inst, kIntRegName[enc.Rm], kAddressSize, Operand::kActionRead,
               0);

  inst.branch_not_taken_pc = inst.pc + 4;
  if (enc.op1 == 0b01) {
    if (is_cond && (enc.Rm == kLRRegNum)) {
      inst.category = Instruction::kCategoryConditionalFunctionReturn;
    } else if (enc.Rm == kLRRegNum) {
      inst.category = Instruction::kCategoryFunctionReturn;
    } else if (is_cond) {
      inst.category = Instruction::kCategoryConditionalIndirectJump;
    } else {
      inst.category = Instruction::kCategoryIndirectJump;
    }
    // BX destination is allowed to be the PC
    if (enc.Rm == kPCRegNum) {
      inst.branch_taken_pc = inst.pc + 4;
    }
  } else if (is_cond) {
    inst.category = Instruction::kCategoryConditionalIndirectFunctionCall;
  } else {
    inst.category = Instruction::kCategoryIndirectFunctionCall;
  }

  AddAddrRegOp(inst, kNextPCVariableName.data(), kAddressSize,
               Operand::kActionRead, 0);

  Operand::Register reg;
  reg.size = kAddressSize;
  reg.name = remill::kNextPCVariableName;
  auto &next_pc = inst.EmplaceOperand(reg);
  next_pc.action = Operand::kActionWrite;

  if (enc.op1 == 0b11) {
    Operand::Register reg;
    reg.size = kAddressSize;
    reg.name = remill::kReturnPCVariableName;
    auto &next_pc = inst.EmplaceOperand(reg);
    next_pc.action = Operand::kActionWrite;
  }

  return true;
}

// Count Leading Zeros
static bool TryDecodeCLZ(Instruction &inst, uint32_t bits) {
  const Misc enc = {bits};
  if (enc.Rd == kPCRegNum || enc.Rm == kPCRegNum) {

    // if d == 15 || m == 15 then UNPREDICTABLE;
    inst.category = Instruction::kCategoryError;
    return false;
  }
  DecodeCondition(inst, enc.cond);

  AddIntRegOp(inst, enc.Rd, kAddressSize, Operand::kActionWrite);
  AddIntRegOp(inst, enc.Rm, kAddressSize, Operand::kActionRead);

  inst.function = "CLZ";
  inst.category = Instruction::kCategoryNormal;
  return true;
}

static const char *const kSatArith[] = {
    [0b00] = "QADD",
    [0b01] = "QSUB",
    [0b10] = "QDADD",
    [0b11] = "QDSUB",
};

// Integer Saturating Arithmetic
static bool TryDecodeIntegerSaturatingArithmetic(Instruction &inst,
                                                 uint32_t bits) {
  const IntSatArith enc = {bits};

  // if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;
  if (enc.Rd == kPCRegNum || enc.Rm == kPCRegNum || enc.Rn == kPCRegNum) {
    inst.category = Instruction::kCategoryError;
    return false;
  }
  DecodeCondition(inst, enc.cond);
  AddIntRegOp(inst, enc.Rd, kAddressSize, Operand::kActionWrite);
  AddIntRegOp(inst, enc.Rm, kAddressSize, Operand::kActionRead);
  AddIntRegOp(inst, enc.Rn, kAddressSize, Operand::kActionRead);

  inst.function = kSatArith[enc.opc];
  inst.category = Instruction::kCategoryNormal;
  return true;
}

// Saturate 16-bit
static bool TryDecodeSat16(Instruction &inst, uint32_t bits) {
  const Sat16 enc = {bits};
  DecodeCondition(inst, enc.cond);

  // if d == 15 || n == 15 then UNPREDICTABLE;
  if (enc.Rd == kPCRegNum || enc.Rn == kPCRegNum) {
    inst.category = Instruction::kCategoryError;
    return false;
  }

  AddIntRegOp(inst, enc.Rd, kAddressSize, Operand::kActionWrite);
  if (enc.U) {
    inst.function = "USAT16";
    AddImmOp(inst, enc.sat_imm);
  } else {
    inst.function = "SSAT16";
    AddImmOp(inst, enc.sat_imm + 1);
  }
  AddIntRegOp(inst, enc.Rn, kAddressSize, Operand::kActionRead);

  inst.category = Instruction::kCategoryNormal;
  return true;
}

// Saturate 32-bit
static bool TryDecodeSat32(Instruction &inst, uint32_t bits) {
  const Sat32 enc = {bits};
  DecodeCondition(inst, enc.cond);

  // if d == 15 || n == 15 then UNPREDICTABLE;
  if (enc.Rd == kPCRegNum || enc.Rn == kPCRegNum) {
    inst.category = Instruction::kCategoryError;
    return false;
  }

  AddIntRegOp(inst, enc.Rd, kAddressSize, Operand::kActionWrite);
  if (enc.U) {
    inst.function = "USAT";
    AddImmOp(inst, enc.sat_imm);
  } else {
    inst.function = "SSAT";
    AddImmOp(inst, enc.sat_imm + 1);
  }
  // (shift_t, shift_n) = DecodeImmShift(sh:'0', imm5);
  AddShiftRegImmOperand(inst, enc.Rn, enc.sh << 1, enc.imm5, 0u, true);

  inst.category = Instruction::kCategoryNormal;
  return true;
}

// U op  Rn == 15
// 0 00  != 1111  SXTAB16
// 0 00  1111     SXTB16
// 0 10  != 1111  SXTAB
// 0 10  1111     SXTB
// 0 11  != 1111  SXTAH
// 0 11  1111     SXTH
// 1 00  != 1111  UXTAB16
// 1 00  1111     UXTB16
// 1 10  != 1111  UXTAB
// 1 10  1111     UXTB
// 1 11  != 1111  UXTAH
// 1 11  1111     UXTH
static const char *kExtAdd(uint32_t index) {
  switch (index) {
    case 0b0000: return "SXTAB16";
    case 0b0001: return "SXTB16";
    case 0b0100: return "SXTAB";
    case 0b0101: return "SXTB";
    case 0b0110: return "SXTAH";
    case 0b0111: return "SXTH";
    case 0b1000: return "UXTAB16";
    case 0b1001: return "UXTB16";
    case 0b1100: return "UXTAB";
    case 0b1101: return "UXTB";
    case 0b1110: return "UXTAH";
    case 0b1111: return "UXTH";
    default: return nullptr;
  }
}

// Extend and Add
static bool TryExtAdd(Instruction &inst, uint32_t bits) {
  const ExtAdd enc = {bits};
  DecodeCondition(inst, enc.cond);

  auto instruction = kExtAdd(enc.U << 3 | enc.op << 1 | (enc.Rn == kPCRegNum));

  // if d == 15 || m == 15 then UNPREDICTABLE;
  if (!instruction || enc.Rd == kPCRegNum || enc.Rm == kPCRegNum) {
    inst.category = Instruction::kCategoryError;
    return false;
  }
  inst.function = instruction;

  AddIntRegOp(inst, enc.Rd, kAddressSize, Operand::kActionWrite);
  if (enc.Rn != kPCRegNum) {
    AddIntRegOp(inst, enc.Rn, kAddressSize, Operand::kActionRead);
  } else {
    AddImmOp(inst, 0u);
  }
  AddIntRegOp(inst, enc.Rm, kAddressSize, Operand::kActionRead);
  AddImmOp(inst, enc.rot << 3);

  inst.category = Instruction::kCategoryNormal;
  return true;
}

//    Rn
// != 1111  BFI
//   1111   BFC
static const char *const kBitInsert[] = {
    [0b0] = "BFI",
    [0b1] = "BFC",
};

// Bitfield Insert
static bool TryBitInsert(Instruction &inst, uint32_t bits) {
  const BitInsert enc = {bits};
  DecodeCondition(inst, enc.cond);

  inst.function = kBitInsert[enc.Rn == kPCRegNum];

  // if d == 15 then UNPREDICTABLE;
  // If msbit < lsbit then UNPREDICTABLE;
  if (enc.Rd == kPCRegNum || enc.msb < enc.lsb) {
    inst.category = Instruction::kCategoryError;
    return false;
  }

  AddIntRegOp(inst, enc.Rd, kAddressSize, Operand::kActionWrite);
  AddIntRegOp(inst, enc.Rd, kAddressSize, Operand::kActionRead);

  if (enc.Rn != kPCRegNum) {
    AddIntRegOp(inst, enc.Rn, kAddressSize, Operand::kActionRead);
  }

  AddImmOp(inst, enc.msb);
  AddImmOp(inst, enc.lsb);

  inst.category = Instruction::kCategoryNormal;
  return true;
}

// U
// 0 SBFX
// 1 UBFX
static const char *const kBitExt[] = {
    [0b0] = "SBFX",
    [0b1] = "UBFX",
};

// Bitfield Extract
static bool TryBitExtract(Instruction &inst, uint32_t bits) {
  const BitExt enc = {bits};
  DecodeCondition(inst, enc.cond);

  inst.function = kBitExt[enc.U];

  // if d == 15 || n == 15 then UNPREDICTABLE;
  // msbit = lsbit + widthminus1;
  // if msbit > 31 then UNPREDICTABLE;
  if (enc.Rd == kPCRegNum || enc.Rn == kPCRegNum ||
      (enc.lsb + enc.widthm1) > 31) {
    inst.category = Instruction::kCategoryError;
    return false;
  }

  AddIntRegOp(inst, enc.Rd, kAddressSize, Operand::kActionWrite);
  AddIntRegOp(inst, enc.Rn, kAddressSize, Operand::kActionRead);
  AddImmOp(inst, enc.lsb);
  AddImmOp(inst, enc.widthm1);

  inst.category = Instruction::kCategoryNormal;
  return true;
}

// o1  o2
//  0   0     REV
//  0   1   REV16
//  1   0    RBIT
//  1   1   REVSH
static const char *const kRevBitByte[] = {
    [0b00] = "REV",
    [0b01] = "REV16",
    [0b10] = "RBIT",
    [0b11] = "REVSH",
};

// Reverse Bit/Byte
static bool TryReverseBitByte(Instruction &inst, uint32_t bits) {
  const RevBitByte enc = {bits};
  DecodeCondition(inst, enc.cond);

  inst.function = kRevBitByte[enc.o1 << 1 | enc.o2];

  // if d == 15 || m == 15 then UNPREDICTABLE;
  if (enc.Rd == kPCRegNum || enc.Rm == kPCRegNum) {
    inst.category = Instruction::kCategoryError;
    return false;
  }

  AddIntRegOp(inst, enc.Rd, kAddressSize, Operand::kActionWrite);
  AddIntRegOp(inst, enc.Rm, kAddressSize, Operand::kActionRead);


  inst.category = Instruction::kCategoryNormal;
  return true;
}


// op0  op1
// 00xxx     Parallel Arithmetic
// 01000 101 SEL
// 01000 001 UNALLOCATED
// 01000 xx0 PKHBT, PKHTB
// 01001 x01 UNALLOCATED
// 01001 xx0 UNALLOCATED
// 0110x x01 UNALLOCATED
// 0110x xx0 UNALLOCATED
// 01x10 001 Saturate 16-bit
// 01x10 101 UNALLOCATED
// 01x11 x01 Reverse Bit/Byte
// 01x1x xx0 Saturate 32-bit
// 01xxx 111 UNALLOCATED
// 01xxx 011 Extend and Add
// 10xxx     Signed multiply, Divide
// 11000 000 Unsigned Sum of Absolute Differences
// 11000 100 UNALLOCATED
// 11001 x00 UNALLOCATED
// 1101x x00 UNALLOCATED
// 110xx 111 UNALLOCATED
// 1110x 111 UNALLOCATED
// 1110x x00 Bitfield Insert
// 11110 111 UNALLOCATED
// 11111 111 Permanently UNDEFINED
// 1111x x00 UNALLOCATED
// 11x0x x10 UNALLOCATED
// 11x1x x10 Bitfield Extract
// 11xxx 011 UNALLOCATED
// 11xxx x01 UNALLOCATED
static TryDecode *TryMedia(uint32_t bits) {
  const Media enc = {bits};

  // op0 | op1
  switch (enc.op0 >> 3) {
    case 0b00:  //  TODO(Sonya): Parallel Arithmetic
      return nullptr;
    case 0b10: return TryDecodeSignedMultiplyDivide;
  }
  // TODO(Sonya)
  switch (enc.op0 << 3 | enc.op1) {
    case 0b01000101:

      // SEL
    case 0b01000000:
    case 0b01000010:
    case 0b01000100:
    case 0b01000110:

      // PKHBT, PKHTB
      return nullptr;
    case 0b01010001:
    case 0b01110001: return TryDecodeSat16;
    case 0b01011001:
    case 0b01011101:
    case 0b01111001:
    case 0b01111101: return TryReverseBitByte;
    case 0b01010000:
    case 0b01010010:
    case 0b01010100:
    case 0b01010110:
    case 0b01011000:
    case 0b01011010:
    case 0b01011100:
    case 0b01011110:
    case 0b01110000:
    case 0b01110010:
    case 0b01110100:
    case 0b01110110:
    case 0b01111000:
    case 0b01111010:
    case 0b01111100:
    case 0b01111110: return TryDecodeSat32;
    case 0b01000011:
    case 0b01001011:
    case 0b01010011:
    case 0b01011011:
    case 0b01100011:
    case 0b01101011:
    case 0b01110011:
    case 0b01111011: return TryExtAdd;
    case 0b11000000:

      // Unsigned Sum of Absolute Differences
      return nullptr;
    case 0b11100000:
    case 0b11100100:
    case 0b11101000:
    case 0b11101100: return TryBitInsert;
    case 0b11111111:

      // Permanently UNDEFINED
      return nullptr;
    case 0b11010010:
    case 0b11010110:
    case 0b11011010:
    case 0b11011110:
    case 0b11110010:
    case 0b11110110:
    case 0b11111010:
    case 0b11111110: return TryBitExtract;
    default: return nullptr;
  }
}

// 00  001 UNALLOCATED
// 00  010 UNALLOCATED
// 00  011 UNALLOCATED
// 00  110 UNALLOCATED
// 01  001 BX
// 01  010 BXJ
// 01  011 BLX (register)
// 01  110 UNALLOCATED
// 10  001 UNALLOCATED
// 10  010 UNALLOCATED
// 10  011 UNALLOCATED
// 10  110 UNALLOCATED
// 11  001 CLZ
// 11  010 UNALLOCATED
// 11  011 UNALLOCATED
// 11  110 ERET
//    111 Exception Generation
//    000 Move special register (register)
//    100 Cyclic Redundancy Check
//    101 Integer Saturating Arithmetic
static TryDecode *TryMiscellaneous(uint32_t bits) {
  const Misc enc = {bits};

  // op0 | op1
  switch (enc.op0 << 3 | enc.op1) {
    case 0b01001:
    case 0b01010:
    case 0b01011: return TryDecodeBX;
    case 0b11001: return TryDecodeCLZ;
    case 0b11110:  // TODO(Sonya): ERET
      return nullptr;
  }
  // TODO(Sonya)
  switch (enc.op1) {
    case 0b111:  // Exception Generation
    case 0b000:  // Move special register (register)
    case 0b100:  // Cyclic Redundancy Check
      return nullptr;
    case 0b101: return TryDecodeIntegerSaturatingArithmetic;
    default: return nullptr;
  }
}

// Corresponds to Data-processing register (immediate shift)
// op0<24 to 23> | op1 <20>
static TryDecode *kDataProcessingRI[] = {
    [0b000] = TryDecodeIntegerDataProcessingRRRI,
    [0b001] = TryDecodeIntegerDataProcessingRRRI,
    [0b010] = TryDecodeIntegerDataProcessingRRRI,
    [0b011] = TryDecodeIntegerDataProcessingRRRI,
    [0b100] = nullptr,  // op0:op1 != 100
    [0b101] = TryIntegerTestAndCompareRRI,
    [0b110] = TryLogicalArithmeticRRRI,
    [0b111] = TryLogicalArithmeticRRRI,
};

// Corresponds to Data-processing register (register shift)
// op0<24 to 23> | op1 <20>
static TryDecode *kDataProcessingRR[] = {
    [0b000] = TryDecodeIntegerDataProcessingRRRR,
    [0b001] = TryDecodeIntegerDataProcessingRRRR,
    [0b010] = TryDecodeIntegerDataProcessingRRRR,
    [0b011] = TryDecodeIntegerDataProcessingRRRR,
    [0b100] = nullptr,  // op0:op1 != 100
    [0b101] = TryIntegerTestAndCompareRRR,
    [0b110] = TryLogicalArithmeticRRRR,
    [0b111] = TryLogicalArithmeticRRRR,
};

// Corresponds to Data-processing immediate
// op0<24 to 23> | op1 <21 to 20>
static TryDecode *kDataProcessingI[] = {
    [0b0000] = TryDecodeIntegerDataProcessingRRI,
    [0b0001] = TryDecodeIntegerDataProcessingRRI,
    [0b0010] = TryDecodeIntegerDataProcessingRRI,
    [0b0011] = TryDecodeIntegerDataProcessingRRI,
    [0b0100] = TryDecodeIntegerDataProcessingRRI,
    [0b0101] = TryDecodeIntegerDataProcessingRRI,
    [0b0110] = TryDecodeIntegerDataProcessingRRI,
    [0b0111] = TryDecodeIntegerDataProcessingRRI,
    [0b1000] = TryDecodeMoveHalfword,
    [0b1001] = TryIntegerTestAndCompareRI,
    [0b1010] = TryMoveSpecialRegisterAndHintsI,
    [0b1011] = TryIntegerTestAndCompareRI,
    [0b1100] = TryLogicalArithmeticRRI,
    [0b1101] = TryLogicalArithmeticRRI,
    [0b1110] = TryLogicalArithmeticRRI,
    [0b1111] = TryLogicalArithmeticRRI,
};

// Corresponds to: Load/Store Word, Unsigned Byte (immediate, literal)
// o2<22> | o1<21>
static TryDecode *kLoadStoreWordUBIL[] = {
    [0b00] = TryDecodeLoadStoreWordUBIL<Operand::kActionWrite,
                                        Operand::kActionRead, 32u>,
    [0b01] = TryDecodeLoadStoreWordUBIL<Operand::kActionRead,
                                        Operand::kActionWrite, 32u, true>,
    [0b10] = TryDecodeLoadStoreWordUBIL<Operand::kActionWrite,
                                        Operand::kActionRead, 8u>,
    [0b11] = TryDecodeLoadStoreWordUBIL<Operand::kActionRead,
                                        Operand::kActionWrite, 8u, true>,
};

// Corresponds to: Load/Store Word, Unsigned Byte (register)
// o2<22> | o1<21>
static TryDecode *kLoadStoreWordUBR[] = {
    [0b00] = TryDecodeLoadStoreWordUBReg<Operand::kActionWrite,
                                         Operand::kActionRead, 32u>,
    [0b01] = TryDecodeLoadStoreWordUBReg<Operand::kActionRead,
                                         Operand::kActionWrite, 32u, true>,
    [0b10] = TryDecodeLoadStoreWordUBReg<Operand::kActionWrite,
                                         Operand::kActionRead, 8u>,
    [0b11] = TryDecodeLoadStoreWordUBReg<Operand::kActionRead,
                                         Operand::kActionWrite, 8u, true>,
};

// Extra load/store
static TryDecode *kExtraLoadStore[] = {
    [0b000001] =
        TryDecodeLoadStoreDualHalfSignedBReg<Operand::kActionWrite,
                                             Operand::kActionRead, 16u>,
    [0b000010] =
        TryDecodeLoadStoreDualHalfSignedBReg<Operand::kActionRead,
                                             Operand::kActionWrite, 64u, true>,
    [0b000011] =
        TryDecodeLoadStoreDualHalfSignedBReg<Operand::kActionWrite,
                                             Operand::kActionRead, 64u>,
    [0b000101] =
        TryDecodeLoadStoreDualHalfSignedBReg<Operand::kActionRead,
                                             Operand::kActionWrite, 16u, true>,
    [0b000110] =
        TryDecodeLoadStoreDualHalfSignedBReg<Operand::kActionRead,
                                             Operand::kActionWrite, 8u, true>,
    [0b000111] =
        TryDecodeLoadStoreDualHalfSignedBReg<Operand::kActionRead,
                                             Operand::kActionWrite, 16u, true>,
    [0b001001] =
        TryDecodeLoadStoreDualHalfSignedBReg<Operand::kActionWrite,
                                             Operand::kActionRead, 16u>,
    [0b001010] = nullptr,
    [0b001011] = nullptr,
    [0b001101] =
        TryDecodeLoadStoreDualHalfSignedBReg<Operand::kActionRead,
                                             Operand::kActionWrite, 16u, true>,
    [0b001110] =
        TryDecodeLoadStoreDualHalfSignedBReg<Operand::kActionRead,
                                             Operand::kActionWrite, 8u, true>,
    [0b001111] =
        TryDecodeLoadStoreDualHalfSignedBReg<Operand::kActionRead,
                                             Operand::kActionWrite, 16u, true>,
    [0b010001] =
        TryDecodeLoadStoreDualHalfSignedBReg<Operand::kActionWrite,
                                             Operand::kActionRead, 16u>,
    [0b010010] =
        TryDecodeLoadStoreDualHalfSignedBReg<Operand::kActionRead,
                                             Operand::kActionWrite, 64u, true>,
    [0b010011] =
        TryDecodeLoadStoreDualHalfSignedBReg<Operand::kActionWrite,
                                             Operand::kActionRead, 64u>,
    [0b010101] =
        TryDecodeLoadStoreDualHalfSignedBReg<Operand::kActionRead,
                                             Operand::kActionWrite, 16u, true>,
    [0b010110] =
        TryDecodeLoadStoreDualHalfSignedBReg<Operand::kActionRead,
                                             Operand::kActionWrite, 8u, true>,
    [0b010111] =
        TryDecodeLoadStoreDualHalfSignedBReg<Operand::kActionRead,
                                             Operand::kActionWrite, 16u, true>,
    [0b011001] =
        TryDecodeLoadStoreDualHalfSignedBReg<Operand::kActionWrite,
                                             Operand::kActionRead, 16u>,
    [0b011010] =
        TryDecodeLoadStoreDualHalfSignedBReg<Operand::kActionRead,
                                             Operand::kActionWrite, 64u, true>,
    [0b011011] =
        TryDecodeLoadStoreDualHalfSignedBReg<Operand::kActionWrite,
                                             Operand::kActionRead, 64u>,
    [0b011101] =
        TryDecodeLoadStoreDualHalfSignedBReg<Operand::kActionRead,
                                             Operand::kActionWrite, 16u, true>,
    [0b011110] =
        TryDecodeLoadStoreDualHalfSignedBReg<Operand::kActionRead,
                                             Operand::kActionWrite, 8u, true>,
    [0b011111] =
        TryDecodeLoadStoreDualHalfSignedBReg<Operand::kActionRead,
                                             Operand::kActionWrite, 16u, true>,
    [0b100001] = TryDecodeLoadStoreDualHalfSignedBIL<Operand::kActionWrite,
                                                     Operand::kActionRead, 16u>,
    [0b100010] =
        TryDecodeLoadStoreDualHalfSignedBIL<Operand::kActionRead,
                                            Operand::kActionWrite, 64u, true>,
    [0b100011] = TryDecodeLoadStoreDualHalfSignedBIL<Operand::kActionWrite,
                                                     Operand::kActionRead, 64u>,
    [0b100101] =
        TryDecodeLoadStoreDualHalfSignedBIL<Operand::kActionRead,
                                            Operand::kActionWrite, 16u, true>,
    [0b100110] =
        TryDecodeLoadStoreDualHalfSignedBIL<Operand::kActionRead,
                                            Operand::kActionWrite, 8u, true>,
    [0b100111] =
        TryDecodeLoadStoreDualHalfSignedBIL<Operand::kActionRead,
                                            Operand::kActionWrite, 16u, true>,
    [0b101001] = TryDecodeLoadStoreDualHalfSignedBIL<Operand::kActionWrite,
                                                     Operand::kActionRead, 16u>,
    [0b101010] = TryDecodeLoadStoreDualHalfSignedBIL<
        Operand::kActionRead, Operand::kActionWrite, 16u,
        true>,  // only valid for Rn == 15 (PC)
    [0b101011] = nullptr,
    [0b101101] =
        TryDecodeLoadStoreDualHalfSignedBIL<Operand::kActionRead,
                                            Operand::kActionWrite, 16u, true>,
    [0b101110] =
        TryDecodeLoadStoreDualHalfSignedBIL<Operand::kActionRead,
                                            Operand::kActionWrite, 8u, true>,
    [0b101111] =
        TryDecodeLoadStoreDualHalfSignedBIL<Operand::kActionRead,
                                            Operand::kActionWrite, 16u, true>,
    [0b110001] = TryDecodeLoadStoreDualHalfSignedBIL<Operand::kActionWrite,
                                                     Operand::kActionRead, 16u>,
    [0b110010] =
        TryDecodeLoadStoreDualHalfSignedBIL<Operand::kActionRead,
                                            Operand::kActionWrite, 64u, true>,
    [0b110011] = TryDecodeLoadStoreDualHalfSignedBIL<Operand::kActionWrite,
                                                     Operand::kActionRead, 64u>,
    [0b110101] =
        TryDecodeLoadStoreDualHalfSignedBIL<Operand::kActionRead,
                                            Operand::kActionWrite, 16u, true>,
    [0b110110] =
        TryDecodeLoadStoreDualHalfSignedBIL<Operand::kActionRead,
                                            Operand::kActionWrite, 8u, true>,
    [0b110111] =
        TryDecodeLoadStoreDualHalfSignedBIL<Operand::kActionRead,
                                            Operand::kActionWrite, 16u, true>,
    [0b111001] = TryDecodeLoadStoreDualHalfSignedBIL<Operand::kActionWrite,
                                                     Operand::kActionRead, 16u>,
    [0b111010] =
        TryDecodeLoadStoreDualHalfSignedBIL<Operand::kActionRead,
                                            Operand::kActionWrite, 64u, true>,
    [0b111011] = TryDecodeLoadStoreDualHalfSignedBIL<Operand::kActionWrite,
                                                     Operand::kActionRead, 64u>,
    [0b111101] =
        TryDecodeLoadStoreDualHalfSignedBIL<Operand::kActionRead,
                                            Operand::kActionWrite, 16u, true>,
    [0b111110] =
        TryDecodeLoadStoreDualHalfSignedBIL<Operand::kActionRead,
                                            Operand::kActionWrite, 8u, true>,
    [0b111111] =
        TryDecodeLoadStoreDualHalfSignedBIL<Operand::kActionRead,
                                            Operand::kActionWrite, 16u, true>,
};

// Load Store Multiple <P> | <U> | <op> | <L>
static TryDecode *kMLoadStore[] = {
    [0b0000] = TryDecodeLoadStoreMultiple<Operand::kActionWrite,
                                          Operand::kActionRead>,  //"STMDA",
    [0b0001] =
        TryDecodeLoadStoreMultiple<Operand::kActionRead, Operand::kActionWrite,
                                   true>,  //"LDMDA",
    [0b0010] = nullptr,  //"STMu", // (User registers)
    [0b0011] = nullptr,  //"LDM", // (User registers) || (exception return)
    [0b0100] = TryDecodeLoadStoreMultiple<Operand::kActionWrite,
                                          Operand::kActionRead>,  //"STM",
    [0b0101] = TryDecodeLoadStoreMultiple<Operand::kActionRead,
                                          Operand::kActionWrite, true>,
    [0b0110] = nullptr,  //"STMu", // (User registers)
    [0b0111] = nullptr,  //"LDM", // (User registers) || (exception return)
    [0b1000] =
        TryDecodeLoadStoreMultiple<Operand::kActionWrite, Operand::kActionRead>,
    [0b1001] =
        TryDecodeLoadStoreMultiple<Operand::kActionRead, Operand::kActionWrite,
                                   true>,  //"LDMDB",
    [0b1010] = nullptr,  //"STMu", // (User registers)
    [0b1011] = nullptr,  //"LDM", // (User registers) || (exception return)
    [0b1100] = TryDecodeLoadStoreMultiple<Operand::kActionWrite,
                                          Operand::kActionRead>,  //"STMIB",
    [0b1101] =
        TryDecodeLoadStoreMultiple<Operand::kActionRead, Operand::kActionWrite,
                                   true>,  //"LDMIB",
    [0b1110] = nullptr,  //"STMu", // (User registers)
    [0b1111] = nullptr,  //"LDM", // (User registers) || (exception return)
};

// Corresponds to: Data-processing and miscellaneous instructions
// op0   op1    op2 op3  op4
// 0            1 != 00  1 Extra load/store
// 0     0xxxx  1    00  1 Multiply and Accumulate
// 0     1xxxx  1    00  1 Synchronization primitives and Load-Acquire/Store-Release
// 0     10xx0  0          Miscellaneous
// 0     10xx0  1        0 Halfword Multiply and Accumulate
// 0  != 10xx0           0 Data-processing register (immediate shift)
// 0  != 10xx0  0        1 Data-processing register (register shift)
// 1                       Data-processing immediate
static TryDecode *TryDataProcessingAndMisc(uint32_t bits) {
  const DataProcessingAndMisc enc = {bits};

  // op0 == 0
  if (!enc.op0) {

    // op2 == 1, op4 == 1
    if (enc.op2 && enc.op4) {

      // Extra load/store -- op3 != 00
      if (enc.op3) {

        // Index with <22> | P <24> | W <21> | o1 <20> | op2 != 00 <6:5>
        return kExtraLoadStore[(((enc.op1 >> 2) & 0b1) << 5) |
                               ((enc.op1 >> 4) << 4) |
                               (((enc.op1 >> 1) & 0b1) << 3) |
                               ((enc.op1 & 0b1) << 2) | enc.op3];

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
    return kDataProcessingI[((enc.op1 >> 1) & 0b1100u) | (enc.op1 & 0b11u)];
  }
}

// This is the top level of the instruction encoding schema for AArch32.
// Instructions are grouped into subsets based on this the top level and then
// into smaller sets.
//   cond op0 op1
// != 1111 00x     Data-processing and miscellaneous instructions
// != 1111 010     Load/Store Word, Unsigned Byte (immediate, literal)
// != 1111 011 0   Load/Store Word, Unsigned Byte (register)
// != 1111 011 1   Media instructions
//        10x     Branch, branch with link, and block data transfer
//        11x     System register access, Advanced SIMD, floating-point, and Supervisor call
//   1111 0xx     Unconditional instructions
static TryDecode *TryDecodeTopLevelEncodings(uint32_t bits) {
  const TopLevelEncodings enc = {bits};

  // op0 == 0xx
  if (!(enc.op0 >> 2)) {
    if (enc.cond != 0b1111u) {

      // Data-processing and miscellaneous instructions -- op0 == 00x
      if (!(enc.op0 >> 1)) {
        return TryDataProcessingAndMisc(bits);

      // Load/Store Word, Unsigned Byte (immediate, literal) -- op0 == 010
      } else if (enc.op0 == 0b010u) {
        const LoadStoreWUBIL enc_ls_word = {bits};
        return kLoadStoreWordUBIL[enc_ls_word.o2 << 1u | enc_ls_word.o1];

      // Load/Store Word, Unsigned Byte (register) -- op0 == 011, op1 == 0
      } else if (!enc.op1) {
        const LoadStoreWUBR enc_ls_word = {bits};
        return kLoadStoreWordUBR[enc_ls_word.o2 << 1u | enc_ls_word.o1];

      // Media instructions -- op0 == 011, op1 == 1
      } else {
        return TryMedia(bits);
      }
    // TODO(Sonya): Unconditional instructions -- cond == 1111
    } else {
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

      // Load/Store Multiple -- cond != 1111, op0 == 100
      } else {
        const LoadStoreM enc_ls_word = {bits};
        return kMLoadStore[enc_ls_word.P << 3 | enc_ls_word.U << 2 |
                           enc_ls_word.op << 1 | enc_ls_word.L];
      }
    // TODO(Sonya): System register access, Advanced SIMD, floating-point, and Supervisor call -- op0 == 11x
    } else {
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
}  // namespace

// Decode an instruction
bool AArch32Arch::DecodeInstruction(uint64_t address,
                                    std::string_view inst_bytes,
                                    Instruction &inst) const {

  inst.pc = address;
  inst.next_pc = address + inst_bytes.size();  // Default fall-through.
  inst.branch_taken_pc = 0;
  inst.branch_not_taken_pc = 0;
  inst.has_branch_taken_delay_slot = false;
  inst.has_branch_not_taken_delay_slot = false;
  inst.arch_name = arch_name;
  inst.sub_arch_name = arch_name;  // TODO(pag): Thumb.
  inst.arch = this;
  inst.category = Instruction::kCategoryInvalid;
  inst.operands.clear();

  if (4ull > inst_bytes.size()) {
    return false;
  }

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
    LOG(ERROR) << "unhandled bits " << std::hex << bits << std::dec;
    return false;
  }

  auto ret = decoder(inst, bits);

  //  LOG(ERROR) << inst.Serialize();
  return ret;
}

}  // namespace remill
