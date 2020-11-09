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

//Integer Data Processing (three register, register shift)
//union IntDataProcessingRRRR {
//  uint32_t flat;
//  struct {
//    uint32_t rm : 4;
//    uint32_t _1 : 1;
//    uint32_t type : 2;
//    uint32_t _0 : 1;
//    uint32_t rs : 4;
//    uint32_t rd : 4;
//    uint32_t rn : 4;
//    uint32_t s : 1;
//    uint32_t opc : 3;
//    uint32_t _0000 : 4;
//    uint32_t cond : 4;
//  } __attribute__((packed));
//} __attribute__((packed));
//static_assert(sizeof(IntDataProcessingRRRR) == 4, " ");

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
//union IntTestCompRRR {
//  uint32_t flat;
//  struct {
//    uint32_t rm : 4;
//    uint32_t _1 : 1;
//    uint32_t type : 2;
//    uint32_t _0 : 1;
//    uint32_t rs : 4;
//    uint32_t _0000 : 4;
//    uint32_t rn  : 4;
//    uint32_t _1a : 1;
//    uint32_t opc : 2;
//    uint32_t _00010 : 5;
//    uint32_t cond : 4;
//  } __attribute__((packed));
//} __attribute__((packed));
//static_assert(sizeof(IntTestCompRRR) == 4, " ");

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
//union LogicalArithRRRR {
//  uint32_t flat;
//  struct {
//    uint32_t rm  : 4;
//    uint32_t _1 : 1;
//    uint32_t type : 2;
//    uint32_t _0 : 1;
//    uint32_t rs : 4;
//    uint32_t rd : 4;
//    uint32_t rn  : 4;
//    uint32_t s : 1;
//    uint32_t opc : 2;
//    uint32_t _00011 : 5;
//    uint32_t cond : 4;
//  } __attribute__((packed));
//} __attribute__((packed));
//static_assert(sizeof(LogicalArithRRRR) == 4, " ");

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

static void AddImmOp(Instruction &inst, uint64_t value, unsigned size = 32,
                     Operand::Action action = Operand::kActionRead,
                     bool is_signed = false) {
  inst.operands.emplace_back();
  auto &op = inst.operands.back();
  op.imm.val = value;
  op.size = size;
  op.imm.is_signed = is_signed;
  op.action = action;
  op.type = Operand::kTypeImmediate;
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

static void AddExtractThenShiftOp(Instruction &inst,
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
  shift_reg.shift_first = false;
  auto &op = inst.EmplaceOperand(shift_reg);
  op.action = Operand::kActionRead;
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

// Note: This function adds either 1 or 2 operands in total
// an op and an optional additional carry_out op
// Used to handle semantics for:
// (imm32, carry) = A32ExpandImm_C(imm12, PSTATE.C);
// See an instruction in Data-processing register (immediate shift) for example
static void ExpandTo32AddImmAddCarry(Instruction &inst, uint32_t imm12, bool carry_out) {
  uint32_t unrotated_value = imm12 & (0b11111111u);
  uint32_t rotation_amount = ((imm12 >> 8) & (0b1111u)) *2u;

  if (!rotation_amount) {
    AddImmOp(inst, unrotated_value);
  } else {
    AddImmOp(inst, __builtin_rotateright32(unrotated_value, rotation_amount));
  }

  if (carry_out) {
    if (!rotation_amount) {
      AddShiftThenExtractOp(inst, Operand::ShiftRegister::kShiftLeftWithZeroes,
                            Operand::ShiftRegister::kExtendUnsigned, "C", 8, 0,
                            1);
    } else {
      AddImmOp(inst,
               (unrotated_value >> ((rotation_amount + 31u) % 32u)) & 0b1u);
    }
  }
}

// Note: This function should be used with AddShiftCarryOperand to add carry_out operand!
// Used to handle semantics for:
// (shifted, carry) = Shift_C(R[m], shift_t, shift_n, PSTATE.C);
// (shift_t, shift_n) = DecodeImmShift(type, imm5);
// See an instruction in Integer Data Processing (three register, immediate shift) set for an example
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
}


// PLEASE SEE AddShiftRegOperand!
// This function extracts the carry_out that from the semantics that
// AddShiftRegOperand handles
static void AddShiftCarryOperand(Instruction &inst,
                                 uint32_t reg_num, uint32_t shift_type,
                                 uint32_t shift_size, const char * carry_reg_name) {

  auto is_rrx = false;
  if (!shift_size && shift_type == Shift::kShiftROR) {
    shift_size = 1;
    is_rrx = true;
  }

  if (!shift_size) {
    AddShiftThenExtractOp(inst, Operand::ShiftRegister::kShiftLeftWithZeroes,
                          Operand::ShiftRegister::kExtendUnsigned,
                          carry_reg_name, 8, 0, 1);
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
          AddShiftThenExtractOp(inst,
                                Operand::ShiftRegister::kShiftUnsignedRight,
                                Operand::ShiftRegister::kExtendUnsigned,
                                kIntRegName[reg_num], 32, 0, 1);
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
                       InstEval *evaluator) {
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
          inst.category = Instruction::kCategoryIndirectJump;
        } else if (!inst.conditions.empty()) {
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
  DecodeCondition(inst, enc.cond);
  AddIntRegOp(inst, enc.rd, 32, Operand::kActionWrite);
  AddIntRegOp(inst, enc.rn, 32, Operand::kActionRead);
  AddShiftRegOperand(inst, enc.rm, enc.type, enc.imm5);

  if (enc.s) {
    AddShiftCarryOperand(inst, enc.rm, enc.type, enc.imm5, "C");
  }

  return EvalPCDest(inst, enc.s, enc.rd, kIdpEvaluators[enc.opc]);
}

// TODO(Sonya): Integer Data Processing (three register, register shift)
//static bool TryDecodeIntegerDataProcessingRRRR(Instruction &inst, uint32_t bits) {
//  return false;
//  const IntDataProcessingRRRR enc = { bits };
//
//  inst.function = kIdpNamesRRR[(enc.opc << 1u) | enc.s];
//  DecodeCondition(inst, enc.cond);
//
//  if (enc.rn == kPCRegNum || enc.rd == kPCRegNum || enc.rs == kPCRegNum
//      || enc.rm == kPCRegNum) {
//    inst.category = Instruction::kCategoryError;
//    return false;
//  }
//}

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
  DecodeCondition(inst, enc.cond);
  AddIntRegOp(inst, enc.rd, 32, Operand::kActionWrite);

  // Raise the program counter to align to a multiple of 4 bytes
  if (enc.rn == kPCRegNum && (enc.opc == 0b100u || enc.opc == 0b010u)) {
    int64_t diff = static_cast<int32_t>(inst.pc & ~(3u)) - static_cast<int32_t>(inst.pc);
    AddAddrRegOp(inst, "PC", 32, Operand::kActionRead, diff);
  } else {
    AddIntRegOp(inst, enc.rn, 32, Operand::kActionRead);
  }

  ExpandTo32AddImmAddCarry(inst, enc.imm12, enc.s);

  return EvalPCDest(inst, enc.s, enc.rd, kIdpEvaluators[enc.opc]);
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
  DecodeCondition(inst, enc.cond);

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

  inst.category = Instruction::kCategoryNormal;
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
  DecodeCondition(inst, enc.cond);

  AddIntRegOp(inst, enc.rd, 32, Operand::kActionWrite);

  // enc.opc == x0
  if (!(enc.opc & 0b1u)) {
    AddIntRegOp(inst, enc.rn, 32, Operand::kActionRead);
  }
  // enc.opc == 01
  else if (!(enc.opc & 0b10u)) {
    AddImmOp(inst, 0);
  }
  // enc.opc == 11
  else {
    AddImmOp(inst, 1);
  }

  AddShiftRegOperand(inst, enc.rm, enc.type, enc.imm5);
  if (enc.s) {
    AddShiftCarryOperand(inst, enc.rm, enc.type, enc.imm5, "C");
  }

  return EvalPCDest(inst, enc.s, enc.rd, kLogArithEvaluators[enc.opc >> 1u]);
}

// TODO(Sonya): Logical Arithmetic (three register, register shift)
//static bool TryLogicalArithmeticRRRR(Instruction &inst, uint32_t bits) {
//  return false;
//
//  const LogicalArithRRRR enc = { bits };
//
//  auto instruction = kLogicalArithmeticRRRI[enc.opc << 1u | enc.s];
//
//  inst.function = instruction;
//  DecodeCondition(inst, enc.cond);
//
//  if (enc.rn == kPCRegNum || enc.rd == kPCRegNum || enc.rs == kPCRegNum
//      || enc.rm == kPCRegNum) {
//    inst.category = Instruction::kCategoryError;
//    return false;
//  }
//
//  AddIntRegOp(inst, enc.rd, 32, Operand::kActionWrite);
//  // enc.opc == x0
//  if (!(enc.opc & 0b1u)) {
//    AddIntRegOp(inst, enc.rn, 32, Operand::kActionRead);
//  }
//  // enc.opc == 01
//  else if (!(enc.opc & 0b10u)) {
//    AddImmOp(inst, 0);
//  }
//  // enc.opc == 11
//  else {
//    AddImmOp(inst, 1);
//  }
//}

// Logical Arithmetic (two register and immediate)
static bool TryLogicalArithmeticRRI(Instruction &inst, uint32_t bits) {
  const LogicalArithmeticRRI enc = { bits };

  auto instruction = kLogicalArithmeticRRRI[enc.opc | enc.s];

  inst.function = instruction;
  DecodeCondition(inst, enc.cond);

  AddIntRegOp(inst, enc.rd, 32, Operand::kActionWrite);
  // enc.opc == x0
  if (!(enc.opc & 0b1u)) {
    AddIntRegOp(inst, enc.rn, 32, Operand::kActionRead);
  }
  // enc.opc == 01
  else if (!(enc.opc & 0b10u)) {
    AddImmOp(inst, 0);
  }
  // enc.opc == 11
  else {
    AddImmOp(inst, 1);
  }

  ExpandTo32AddImmAddCarry(inst, enc.imm12, enc.s);

  return EvalPCDest(inst, enc.s, enc.rd, kLogArithEvaluators[enc.opc >> 1u]);
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
  AddShiftRegOperand(inst, enc.rm, enc.type, enc.imm5);
  AddShiftCarryOperand(inst, enc.rm, enc.type, enc.imm5, "C");

  inst.category = Instruction::kCategoryNormal;
  return true;
}

// TODO(Sonya): Integer Test and Compare (two register, register shift)
//static bool TryIntegerTestAndCompareRRR(Instruction &inst, uint32_t bits) {
//  return false;
//
//  const IntTestCompRRR enc = { bits };
//
//  auto instruction = kIntegerTestAndCompareR[enc.opc];
//
//  inst.function = instruction;
//  DecodeCondition(inst, enc.cond);
//
//  if (enc.rn == kPCRegNum || enc.rs == kPCRegNum || enc.rm == kPCRegNum) {
//      inst.category = Instruction::kCategoryError;
//      return false;
//  }
//}
//
//// Integer Test and Compare (one register and immediate)
//static bool TryIntegerTestAndCompareRI(Instruction &inst, uint32_t bits) {
//  const IntTestCompRI enc = { bits };
//
//  auto instruction = kIntegerTestAndCompareR[enc.opc];
//
//  inst.function = instruction;
//  DecodeCondition(inst, enc.cond);
//
//  AddIntRegOp(inst, enc.rn, 32, Operand::kActionRead);
//  ExpandTo32AddImmAddCarry(inst, enc.imm12, 1u);
//
//  inst.category = Instruction::kCategoryNormal;
//  return true;
//
//}

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

// Corresponds to Data-processing register (immediate shift)
// op0<24 to 23> | op1 <20>
static TryDecode * kDataProcessingRR[] = {
    [0b000] = nullptr, //TryDecodeIntegerDataProcessingRRRR,
    [0b001] = nullptr, //TryDecodeIntegerDataProcessingRRRR,
    [0b010] = nullptr, //TryDecodeIntegerDataProcessingRRRR,
    [0b011] = nullptr, //TryDecodeIntegerDataProcessingRRRR,
    [0b100] = nullptr, // op0:op1 != 100
    [0b101] = nullptr, //TryIntegerTestAndCompareRRR,
    [0b110] = nullptr, //TryLogicalArithmeticRRRR,
    [0b111] = nullptr, //TryLogicalArithmeticRRRR,
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
    [0b1001] = nullptr, //TryIntegerTestAndCompareRI,
    [0b1010] = nullptr, // TODO(Sonya): Move Special Register and Hints (immediate)
    [0b1011] = nullptr, // TryIntegerTestAndCompareRI,
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
      }
      // op3 == 00
      else {
        // Multiply and Accumulate -- op1 == 0xxxx
        if (!(enc.op1 >> 4)) {
          return TryDecodeMultiplyAndAccumulate;
        }
        // TODO(Sonya): Synchronization primitives and Load-Acquire/Store-Release -- op1 == 1xxxx
        else {
          return nullptr;
        }
      }
    }
    // op1 == 10xx0
    else if (((enc.op1 >> 3) == 0b10u) && (enc.op1 & 0b00001u)) {
      // TODO(Sonya): Miscellaneous
      if (!enc.op2) {
        return nullptr;
      }
      // TODO(Sonya): Halfword Multiply and Accumulate
      else {
        return nullptr;
      }
    }
    // op1 != 10xx0
    else {
      // Data-processing register (immediate shift) -- op4 == 0
      if (!enc.op4) {
        // op0 -> enc.op1 2 high order bits, op1 -> enc.op1 lowest bit
        // index is the concatenation of op0 and op1
        return kDataProcessingRI[(enc.op1 >> 2) | (enc.op1 & 0b1u)];
      }
      // Data-processing register (register shift) -- op4 == 1
      else {
        return kDataProcessingRR[(enc.op1 >> 2) | (enc.op1 & 0b1u)];
      }
    }
  }
  // Data-processing immediate -- op0 == 1
  else {
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
      }
      // Load/Store Word, Unsigned Byte (immediate, literal) -- op0 == 010
      else if (enc.op0 == 0b010u) {
        const LoadStoreWUBIL enc_ls_word = { bits };
        return kLoadStoreWordUBIL[enc_ls_word.o2 << 1u | enc_ls_word.o1];
      }
      // TODO(Sonya): Load/Store Word, Unsigned Byte (register) -- op0 == 011, op1 == 0
      else if (!enc.op1) {
        // This should be returning another table index using a struct like above
        return nullptr;
      }
      // TODO(Sonya): Media instructions -- op0 == 011, op1 == 1
      else {
        // return a result from another function for instruction categorizing
        return nullptr;
      }
    }
    // TODO(Sonya): Unconditional instructions -- cond == 1111
    else {
      // return a result from another function for instruction categorizing
      return nullptr;
    }
  }
  // op0 == 1xx
  else {
    // TODO(Sonya): Branch, branch with link, and block data transfer -- op0 == 10x
    if (enc.op0 >> 1 == 0b10u) {
      // return a result from another function for instruction categorizing
      return nullptr;
    }
    // TODO(Sonya): System register access, Advanced SIMD, floating-point, and Supervisor call -- op0 == 11x
    else {
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
  inst.arch_for_decode = this;
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
