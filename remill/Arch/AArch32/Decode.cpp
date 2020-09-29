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

#include <glog/logging.h>

namespace remill {

namespace {

//Integer Data Processing (three register, immediate shift)
union IntDataProcessingRRR {
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
static_assert(sizeof(IntDataProcessingRRR) == 4, " ");

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

static constexpr auto kPCRegNum = 15u;

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

static void DecodeA32ExpandImm(Instruction &inst, uint32_t imm12, bool carry_out) {
  uint32_t unrotated_value = imm12 & (0b11111111u);
  uint32_t rotation_amount = ((imm12 >> 8) & (0b1111u)) *2u;
  auto num_ops = inst.operands.size();
  inst.operands.emplace_back();
  inst.operands.emplace_back();
  inst.operands.emplace_back();
  auto &op0 = inst.operands[num_ops];
  auto &op1 = inst.operands[num_ops + 1];
  auto &op2 = inst.operands[num_ops + 2];

  op0.imm.is_signed = false;
  op0.size = 32;
  op0.action = Operand::kActionRead;
  op0.type = Operand::kTypeImmediate;

  if (!rotation_amount) {
    op0.imm.val = unrotated_value;
  } else {
    op0.imm.val = __builtin_rotateright32(unrotated_value, rotation_amount);
  }

  // This is the 2nd part of RRX so we can reuse the same semantics
  op1.imm.is_signed = false;
  op1.imm.val = 0;
  op1.size = 32;
  op1.action = Operand::kActionRead;
  op1.type = Operand::kTypeImmediate;

  if (!rotation_amount) {
    op2.shift_reg.extract_size = 1;
    op2.shift_reg.extend_op = Operand::ShiftRegister::kExtendUnsigned;

    op2.shift_reg.shift_size = 0;
    op2.type = Operand::kTypeShiftRegister;
    op2.size = 32;
    op2.action = Operand::kActionRead;

    op2.shift_reg.reg.name = "C";
    op2.shift_reg.reg.size = 8;
    op2.shift_reg.shift_op = Operand::ShiftRegister::kShiftLeftWithZeroes;
    op2.shift_reg.shift_size = 0;
  } else {
    op2.imm.val = (unrotated_value >> ((rotation_amount + 31u) % 32u)) & 0b1u;
    op2.size = 32;
    op2.imm.is_signed = false;
    op2.action = Operand::kActionRead;
    op2.type = Operand::kTypeImmediate;
  }

  if (!carry_out) {
    inst.operands.pop_back();
  }

}

static void AddIntRegOp(Instruction &inst, unsigned index, unsigned size,
                        Operand::Action action) {
  inst.operands.emplace_back();
  auto &op = inst.operands.back();
  op.type = Operand::kTypeRegister;
  op.size = size;
  op.action = action;
  op.reg.size = size;
  op.reg.name = kIntRegName[index];
}

static void AddImmOp(Instruction &inst, uint64_t value, unsigned size = 32,
                        bool is_signed = false) {
  inst.operands.emplace_back();
  auto &op = inst.operands.back();
  op.imm.val = value;
  op.size = size;
  op.imm.is_signed = is_signed;
  op.action = Operand::kActionRead;
  op.type = Operand::kTypeImmediate;
}

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

static void AddShiftRegOperand(Instruction &inst,
                               uint32_t reg_num, uint32_t shift_type,
                               uint32_t shift_size) {
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
    inst.operands.emplace_back();
    auto &op = inst.operands.back();
    op.shift_reg.reg.name = kIntRegName[reg_num];
    op.shift_reg.reg.size = 32;

    if (is_rrx) {
      op.shift_reg.shift_op = Operand::ShiftRegister::kShiftUnsignedRight;
      op.shift_reg.shift_size = 1;
    } else {
      op.shift_reg.shift_op = GetOperandShift(static_cast<Shift>(shift_type));
      op.shift_reg.shift_size = shift_size;
    }

    op.type = Operand::kTypeShiftRegister;
    op.size = 32;
    op.action = Operand::kActionRead;
  }

  // To handle rrx we need to take two components shift each and OR the results
  // together. No single operand type in remill is flexible enough to handle this.
  // So we make 2 operands and OR those two operands together. In most cases
  // when rrx isn't used we OR something with 0.
  inst.operands.emplace_back();
  auto &op = inst.operands.back();
  if (is_rrx) {
    op.shift_reg.reg.name = "C";
    op.shift_reg.reg.size = 8;

    op.shift_reg.shift_op = Operand::ShiftRegister::kShiftLeftWithZeroes;
    op.shift_reg.shift_size = 31;

    op.type = Operand::kTypeShiftRegister;
    op.size = 32;
    op.action = Operand::kActionRead;
  } else {
    op.imm.is_signed = false;
    op.imm.val = 0;
    op.size = 32;
    op.action = Operand::kActionRead;
    op.type = Operand::kTypeImmediate;
  }
}

static void AddShiftCarryOperand(Instruction &inst,
                                 uint32_t reg_num, uint32_t shift_type,
                                 uint32_t shift_size, const char * carry_reg_name) {
  inst.operands.emplace_back();
  auto &op = inst.operands.back();
  op.shift_reg.extract_size = 1;
  op.shift_reg.extend_op = Operand::ShiftRegister::kExtendUnsigned;

  op.shift_reg.shift_size = shift_size;
  op.type = Operand::kTypeShiftRegister;
  op.size = 32;
  op.action = Operand::kActionRead;

  auto is_rrx = false;
  if (!shift_size && shift_type == Shift::kShiftROR) {
    shift_size = 1;
    is_rrx = true;
  }

  if (!shift_size) {
    op.shift_reg.reg.name = carry_reg_name;
    op.shift_reg.reg.size = 8;
    op.shift_reg.shift_op = Operand::ShiftRegister::kShiftLeftWithZeroes;
    op.shift_reg.shift_size = 0;
  } else {
    op.shift_reg.reg.name = kIntRegName[reg_num];
    op.shift_reg.reg.size = 32;
    switch (static_cast<Shift>(shift_type)) {
      case Shift::kShiftASR:
        op.shift_reg.shift_size = shift_size - 1;
        op.shift_reg.shift_op = Operand::ShiftRegister::kShiftSignedRight;
        break;
      case Shift::kShiftLSL:
        op.shift_reg.shift_size = 32 - shift_size;
        op.shift_reg.shift_op = Operand::ShiftRegister::kShiftUnsignedRight;
        break;
      case Shift::kShiftLSR:
        op.shift_reg.shift_size = shift_size - 1;
        op.shift_reg.shift_op = Operand::ShiftRegister::kShiftUnsignedRight;
        break;
      case Shift::kShiftROR:
        if (is_rrx) {
          op.shift_reg.shift_size = 0;
          op.shift_reg.shift_op = Operand::ShiftRegister::kShiftUnsignedRight;
        } else {
          op.shift_reg.shift_size = (shift_size + 31u) % 32u;
          op.shift_reg.shift_op = Operand::ShiftRegister::kShiftUnsignedRight;
        }
        break;
    }
  }
}

// Decode the condition field and fill in the instruction conditions accordingly
static void DecodeCondition(Instruction &inst, uint32_t cond) {
  inst.conditions.emplace_back();
  auto &lhs_cond = inst.conditions.back();

  switch (cond) {
    case 0b0001:
      inst.negate_conditions = true;
      [[clang::fallthrough]];
    case 0b0000: {
      lhs_cond.kind = Condition::kTypeIsOne;
      lhs_cond.lhs_reg.name = "Z";
      lhs_cond.lhs_reg.size = 8;
      break;
    }
    case 0b0011:
      inst.negate_conditions = true;
      [[clang::fallthrough]];
    case 0b0010: {
      lhs_cond.kind = Condition::kTypeIsOne;
      lhs_cond.lhs_reg.name = "C";
      lhs_cond.lhs_reg.size = 8;
      break;
    }
    case 0b0101:
      inst.negate_conditions = true;
      [[clang::fallthrough]];
    case 0b0100: {
      lhs_cond.kind = Condition::kTypeIsOne;
      lhs_cond.lhs_reg.name = "N";
      lhs_cond.lhs_reg.size = 8;
      break;
    }
    case 0b0111:
      inst.negate_conditions = true;
      [[clang::fallthrough]];
    case 0b0110: {
      lhs_cond.kind = Condition::kTypeIsOne;
      lhs_cond.lhs_reg.name = "V";
      lhs_cond.lhs_reg.size = 8;
      break;
    }
    case 0b1001:
      inst.negate_conditions = true;
      [[clang::fallthrough]];
    case 0b1000: {
      lhs_cond.kind = Condition::kTypeIsOne;
      lhs_cond.lhs_reg.name = "C";
      lhs_cond.lhs_reg.size = 8;

      inst.conditions.emplace_back();
      auto &rhs_cond = inst.conditions.back();
      rhs_cond.kind = Condition::kTypeIsZero;
      rhs_cond.rhs_reg.name = "Z";
      rhs_cond.rhs_reg.size = 8;
      break;
    }
    case 0b1011:
      inst.negate_conditions = true;
      [[clang::fallthrough]];
    case 0b1010: {
      lhs_cond.kind = Condition::kTypeIsEqual;
      lhs_cond.lhs_reg.name = "N";
      lhs_cond.lhs_reg.size = 8;

      lhs_cond.rhs_reg.name = "V";
      lhs_cond.rhs_reg.size = 8;
      break;
    }
    case 0b1101:
      inst.negate_conditions = true;
      [[clang::fallthrough]];
    case 0b1100: {
      lhs_cond.kind = Condition::kTypeIsEqual;
      lhs_cond.lhs_reg.name = "N";
      lhs_cond.lhs_reg.size = 8;

      lhs_cond.rhs_reg.name = "V";
      lhs_cond.rhs_reg.size = 8;

      inst.conditions.emplace_back();
      auto &rhs_cond = inst.conditions.back();
      rhs_cond.kind = Condition::kTypeIsZero;
      rhs_cond.rhs_reg.name = "Z";
      rhs_cond.rhs_reg.size = 8;
      break;
    }
    case 0b1111:
    case 0b1110:
      inst.conditions.pop_back();
      break;
    default:
      LOG(FATAL) << "Invalid condition bits " << cond << " in " << inst.Serialize();
      break;
  }
}

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
static bool TryDecodeIntegerDataProcessingRRR(Instruction &inst, uint32_t bits) {
  const IntDataProcessingRRR enc = {bits};
  if (enc.cond == 0b1111u) {
    return false;
  }

  inst.function = kIdpNamesRRR[ (enc.opc << 1u) | enc.s];
  DecodeCondition(inst, enc.cond);
  AddIntRegOp(inst, enc.rd, 32, Operand::kActionWrite);
  AddIntRegOp(inst, enc.rn, 32, Operand::kActionRead);
  AddShiftRegOperand(inst, enc.rm, enc.type, enc.imm5);

  if (enc.s) {
    AddShiftCarryOperand(inst, enc.rm, enc.type, enc.imm5, "C");
  }

  if (enc.rd == kPCRegNum) {
    if (enc.s) {  // Updates the flags (condition codes)
      inst.category = Instruction::kCategoryError;
      return false;
    } else {
      inst.category = Instruction::kCategoryIndirectJump;
    }
  } else {
    inst.category = Instruction::kCategoryNormal;
  }

  return true;
}

//000     AND, ANDS (immediate)
//001     EOR, EORS (immediate)
//010 0 != 11x1 SUB, SUBS (immediate) — SUB
//010 0 1101  SUB, SUBS (SP minus immediate) — SUB
//010 0 1111  ADR — A2
//010 1 != 1101 SUB, SUBS (immediate) — SUBS
//010 1 1101  SUB, SUBS (SP minus immediate) — SUBS
//011     RSB, RSBS (immediate)
//100 0 != 11x1 ADD, ADDS (immediate) — ADD
//100 0 1101  ADD, ADDS (SP plus immediate) — ADD
//100 0 1111  ADR — A1
//100 1 != 1101 ADD, ADDS (immediate) — ADDS
//100 1 1101  ADD, ADDS (SP plus immediate) — ADDS
//101     ADC, ADCS (immediate)
//110     SBC, SBCS (immediate)
//111     RSC, RSCS (immediate)
static bool TryDecodeIntegerDataProcessingRRI(Instruction &inst, uint32_t bits) {
  const IntDataProcessingRRI enc = { bits };
  if (enc.cond == 0b1111u) {
    return false;
  }

  inst.function = kIdpNamesRRR[(enc.opc << 1u) | enc.s];
  DecodeCondition(inst, enc.cond);
  AddIntRegOp(inst, enc.rd, 32, Operand::kActionWrite);

  // Raise the program counter to align to a multiple of 4 bytes
  if (enc.rn == kPCRegNum && (enc.opc == 0b100u || enc.opc == 0b010u)) {
    int64_t diff = static_cast<int32_t>(inst.pc & ~(3u)) - static_cast<int32_t>(inst.pc);

    inst.operands.emplace_back();
    auto &op = inst.operands.back();
    op.type = Operand::kTypeAddress;
    op.size = 32;
    op.action = Operand::kActionRead;
    op.addr.address_size = 32;
    op.addr.base_reg.name = "PC";
    op.addr.base_reg.size = 32;
    op.addr.scale = 0;
    op.addr.displacement = diff;

  } else {
    AddIntRegOp(inst, enc.rn, 32, Operand::kActionRead);
  }

  DecodeA32ExpandImm(inst, enc.imm12, enc.s);

  if (enc.rd == kPCRegNum) {

    if (enc.s) {  // Updates the flags (condition codes)
      inst.category = Instruction::kCategoryError;
      return false;
    } else {
      inst.category = Instruction::kCategoryIndirectJump;
    }
  } else {
    inst.category = Instruction::kCategoryNormal;
  }

  return true;
}


static const char * const kMulAccRRR[] = {
    [0b0000] = "MULrr",
    [0b0001] = "MULSrr",
    [0b0010] = "MLArr",
    [0b0011] = "MLASrr",
    [0b0100] = "UMAALrr",
    [0b0101] = nullptr,
    [0b0110] = "MLSrr",
    [0b0111] = nullptr,
    [0b1000] = "UMULLrr",
    [0b1001] = "UMULLSrr",
    [0b1010] = "UMLALrr",
    [0b1011] = "UMLALSrr",
    [0b1100] = "SMULLrr",
    [0b1101] = "SMULLSrr",
    [0b1110] = "SMLALrr",
    [0b1111] = "SMLALSrr"
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
  // cond != 1111
  // if d == 15 || n == 15 || m == 15 || a == 15 then UNPREDICTABLE;
  if (enc.cond == 0b1111u || (enc.rdhi == kPCRegNum || enc.rn == kPCRegNum || enc.rm == kPCRegNum) || ) {
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
  if (enc.opc != 0b000u || enc.opc != 0b100u || enc.opc != 0b110u) {
    AddIntRegOp(inst, enc.rdlo, 32, Operand::kActionRead);
  } else {
    AddImmOp(inst, 0);
  }

  return true;

}

static bool (*const kBits7_to_4[])(Instruction&, uint32_t) = {
    [0b0000] = TryDecodeIntegerDataProcessingRRR,
    [0b0001] = nullptr,
    [0b0010] = TryDecodeIntegerDataProcessingRRR,
    [0b0011] = nullptr,
    [0b0100] = TryDecodeIntegerDataProcessingRRR,
    [0b0101] = nullptr,
    [0b0110] = TryDecodeIntegerDataProcessingRRR,
    [0b0111] = nullptr,
    [0b1000] = TryDecodeIntegerDataProcessingRRR,
    [0b1001] = TryDecodeMultiplyAndAccumulate,
    [0b1010] = TryDecodeIntegerDataProcessingRRR,
    [0b1011] = nullptr,
    [0b1100] = TryDecodeIntegerDataProcessingRRR,
    [0b1101] = nullptr,
    [0b1110] = TryDecodeIntegerDataProcessingRRR,
    [0b1111] = nullptr
};

static bool TryDecodeArithmetic(Instruction &inst, uint32_t bits){
  auto decode = kBits7_to_4[(bits >> 4) & 0b1111u];
  if (!decode){
    return false;
  }
  return decode(inst, bits);
}

static bool (*const kBits27_to_21[])(Instruction&, uint32_t) = {
  [0b0000000] = TryDecodeArithmetic,
  [0b0000001] = TryDecodeArithmetic,
  [0b0000010] = TryDecodeArithmetic,
  [0b0000011] = TryDecodeArithmetic,
  [0b0000100] = TryDecodeArithmetic,
  [0b0000101] = TryDecodeArithmetic,
  [0b0000110] = TryDecodeArithmetic,
  [0b0000111] = TryDecodeArithmetic,
  [0b0001000] = nullptr,
  [0b0001001] = nullptr,
  [0b0001010] = nullptr,
  [0b0001011] = nullptr,
  [0b0001100] = nullptr,
  [0b0001101] = nullptr,
  [0b0001110] = nullptr,
  [0b0001111] = nullptr,
  [0b0010000] = TryDecodeIntegerDataProcessingRRI,
  [0b0010001] = TryDecodeIntegerDataProcessingRRI,
  [0b0010010] = TryDecodeIntegerDataProcessingRRI,
  [0b0010011] = TryDecodeIntegerDataProcessingRRI,
  [0b0010100] = TryDecodeIntegerDataProcessingRRI,
  [0b0010101] = TryDecodeIntegerDataProcessingRRI,
  [0b0010110] = TryDecodeIntegerDataProcessingRRI,
  [0b0010111] = TryDecodeIntegerDataProcessingRRI,
  [0b0011000] = nullptr,
  [0b0011001] = nullptr,
  [0b0011010] = nullptr,
  [0b0011011] = nullptr,
  [0b0011100] = nullptr,
  [0b0011101] = nullptr,
  [0b0011110] = nullptr,
  [0b0011111] = nullptr,
  [0b0100000] = nullptr,
  [0b0100001] = nullptr,
  [0b0100010] = nullptr,
  [0b0100011] = nullptr,
  [0b0100100] = nullptr,
  [0b0100101] = nullptr,
  [0b0100110] = nullptr,
  [0b0100111] = nullptr,
  [0b0101000] = nullptr,
  [0b0101001] = nullptr,
  [0b0101010] = nullptr,
  [0b0101011] = nullptr,
  [0b0101100] = nullptr,
  [0b0101101] = nullptr,
  [0b0101110] = nullptr,
  [0b0101111] = nullptr,
  [0b0110000] = nullptr,
  [0b0110001] = nullptr,
  [0b0110010] = nullptr,
  [0b0110011] = nullptr,
  [0b0110100] = nullptr,
  [0b0110101] = nullptr,
  [0b0110110] = nullptr,
  [0b0110111] = nullptr,
  [0b0111000] = nullptr,
  [0b0111001] = nullptr,
  [0b0111010] = nullptr,
  [0b0111011] = nullptr,
  [0b0111100] = nullptr,
  [0b0111101] = nullptr,
  [0b0111110] = nullptr,
  [0b0111111] = nullptr,
  [0b1000000] = nullptr,
  [0b1000001] = nullptr,
  [0b1000010] = nullptr,
  [0b1000011] = nullptr,
  [0b1000100] = nullptr,
  [0b1000101] = nullptr,
  [0b1000110] = nullptr,
  [0b1000111] = nullptr,
  [0b1001000] = nullptr,
  [0b1001001] = nullptr,
  [0b1001010] = nullptr,
  [0b1001011] = nullptr,
  [0b1001100] = nullptr,
  [0b1001101] = nullptr,
  [0b1001110] = nullptr,
  [0b1001111] = nullptr,
  [0b1010000] = nullptr,
  [0b1010001] = nullptr,
  [0b1010010] = nullptr,
  [0b1010011] = nullptr,
  [0b1010100] = nullptr,
  [0b1010101] = nullptr,
  [0b1010110] = nullptr,
  [0b1010111] = nullptr,
  [0b1011000] = nullptr,
  [0b1011001] = nullptr,
  [0b1011010] = nullptr,
  [0b1011011] = nullptr,
  [0b1011100] = nullptr,
  [0b1011101] = nullptr,
  [0b1011110] = nullptr,
  [0b1011111] = nullptr,
  [0b1100000] = nullptr,
  [0b1100001] = nullptr,
  [0b1100010] = nullptr,
  [0b1100011] = nullptr,
  [0b1100100] = nullptr,
  [0b1100101] = nullptr,
  [0b1100110] = nullptr,
  [0b1100111] = nullptr,
  [0b1101000] = nullptr,
  [0b1101001] = nullptr,
  [0b1101010] = nullptr,
  [0b1101011] = nullptr,
  [0b1101100] = nullptr,
  [0b1101101] = nullptr,
  [0b1101110] = nullptr,
  [0b1101111] = nullptr,
  [0b1110000] = nullptr,
  [0b1110001] = nullptr,
  [0b1110010] = nullptr,
  [0b1110011] = nullptr,
  [0b1110100] = nullptr,
  [0b1110101] = nullptr,
  [0b1110110] = nullptr,
  [0b1110111] = nullptr,
  [0b1111000] = nullptr,
  [0b1111001] = nullptr,
  [0b1111010] = nullptr,
  [0b1111011] = nullptr,
  [0b1111100] = nullptr,
  [0b1111101] = nullptr,
  [0b1111110] = nullptr,
  [0b1111111] = nullptr,
};


static uint32_t BytesToBits(const uint8_t *bytes) {
  uint32_t bits = 0;
  bits = (bits << 8) | static_cast<uint32_t>(bytes[0]);
  bits = (bits << 8) | static_cast<uint32_t>(bytes[1]);
  bits = (bits << 8) | static_cast<uint32_t>(bytes[2]);
  bits = (bits << 8) | static_cast<uint32_t>(bytes[3]);
  return bits;
}

} // namespace

// Decode an instuction.
bool AArch32Arch::DecodeInstruction(uint64_t address, std::string_view inst_bytes,
                                    Instruction &inst) const {

  inst.pc = address;
  inst.next_pc = address + inst_bytes.size();  // Default fall-through.
  inst.branch_taken_pc = 0;
  inst.branch_not_taken_pc = 0;
  inst.has_branch_taken_delay_slot = false;
  inst.has_branch_not_taken_delay_slot = false;
  inst.arch_name = arch_name;
  inst.arch_for_decode = nullptr;
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

  auto decoder = kBits27_to_21[(bits >> 21) & 0b1111111u];
  if (!decoder) {
    LOG(ERROR) << "unhandled bits";
    return false;
  }

  auto ret = decoder(inst, bits);
  LOG(ERROR) << inst.Serialize();
  return ret;
}

} // namespace remill
