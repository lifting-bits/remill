/*
 * Copyright (c) 2022 Trail of Bits, Inc.
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
#include "Decode.h"
#include "remill/BC/ABI.h"

namespace remill {

namespace aarch32 {

// Add, subtract (three low registers)
union AddSub3LowReg16 {
  uint16_t flat;
  struct {
    uint16_t Rd : 3;
    uint16_t Rn : 3;
    uint16_t Rm : 3;
    uint16_t S : 1;
    uint16_t _000110  : 6;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(AddSub3LowReg16) == 2, " ");

// Add, subtract (two low registers and immediate)
union AddSub2LowRegImm16 {
  uint16_t flat;
  struct {
    uint16_t Rd : 3;
    uint16_t Rn : 3;
    uint16_t imm3 : 3;
    uint16_t S : 1;
    uint16_t _000111  : 6;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(AddSub2LowRegImm16) == 2, " ");

// Add, subtract, compare, move (one low register and immediate)
union AddSubComp1LowRegImm16 {
  uint16_t flat;
  struct {
    uint16_t imm8 : 8;
    uint16_t Rd : 3;
    uint16_t op : 2;
    uint16_t _001  : 3;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(AddSubComp1LowRegImm16) == 2, " ");

// Adjust SP (immediate)
union AdjustSPImm16 {
  uint16_t flat;
  struct {
    uint16_t imm7 : 7;
    uint16_t S : 1;
    uint16_t _10110000 : 8;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(AdjustSPImm16) == 2, " ");

// MOV, MOVS (register) — T2
union MOVrT2_16 {
  uint16_t flat;
  struct {
    uint16_t Rd : 3;
    uint16_t Rm : 3;
    uint16_t imm5 : 5;
    uint16_t op : 2;
    uint16_t _000  : 3;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(MOVrT2_16) == 2, " ");

// Load/store word/byte (immediate offset)
union LoadStoreWordByteImm16 {
  uint16_t flat;
  struct {
    uint16_t Rt : 3;
    uint16_t Rn : 3;
    uint16_t imm5 : 5;
    uint16_t L : 1;
    uint16_t B : 1;
    uint16_t _011  : 3;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(LoadStoreWordByteImm16) == 2, " ");

// Load/store (SP-relative)
union LoadStoreSPRelative16 {
  uint16_t flat;
  struct {
    uint16_t imm8 : 8;
    uint16_t Rt : 3;
    uint16_t L : 1;
    uint16_t _1001  : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(LoadStoreSPRelative16) == 2, " ");

// Add PC/SP (immediate)
union AddPCSPImm16 {
  uint16_t flat;
  struct {
    uint16_t imm8 : 8;
    uint16_t Rd : 3;
    uint16_t SP : 1;
    uint16_t _1010  : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(AddPCSPImm16) == 2, " ");

// Miscellaneous 16-bit instructions
union Misc16 {
  uint16_t flat;
  struct {
    uint16_t op3 : 4;
    uint16_t _b4 : 1;
    uint16_t op2 : 1;
    uint16_t op1 : 2;
    uint16_t op0 : 4;
    uint16_t _1011  : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(Misc16) == 2, " ");

// B — T1
union B_T1_16 {
  uint16_t flat;
  struct {
    uint16_t imm8 : 8;
    uint16_t cond : 4;
    uint16_t _1101   : 4;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(B_T1_16) == 2, " ");

// B — T2
union B_T2_16 {
  uint16_t flat;
  struct {
    uint16_t imm11 : 11;
    uint16_t _11100   : 5;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(B_T2_16) == 2, " ");

// Shift (immediate), add, subtract, move, and compare
union ShiftImmAddSubMoveComp16 {
  uint16_t flat;
  struct {
    uint16_t _9_to_0 : 10;
    uint16_t op2 : 1;
    uint16_t op1 : 2;
    uint16_t op0 : 1;
    uint16_t _00 : 2;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(ShiftImmAddSubMoveComp16) == 2, " ");

// Load/Store Multiple
union LoadStoreMult32 {
  uint32_t flat;
  struct {
    uint32_t register_list : 13;
    uint32_t _0_b13 : 1;
    uint32_t M : 1;
    uint32_t P : 1;
    uint32_t Rn : 4;
    uint32_t L : 1;
    uint32_t W : 1;
    uint32_t _0_b22 : 1;
    uint32_t opc : 2;
    uint32_t _1110100  : 7;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(LoadStoreMult32) == 4, " ");

// BL, BLX (immediate) — T1
union BLT1_32 {
  uint32_t flat;
  struct {
    uint32_t imm11 : 11;
    uint32_t J2 : 1;
    uint32_t _1 : 1;
    uint32_t J1 : 1;
    uint32_t _11 : 2;
    uint32_t imm10 : 10;
    uint32_t S : 1;
    uint32_t _11110  : 5;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(BLT1_32) == 4, " ");

// BL, BLX (immediate) — T2
union BLXT2_32 {
  uint32_t flat;
  struct {
    uint32_t H : 1;
    uint32_t imm10L : 10;
    uint32_t J2 : 1;
    uint32_t _0 : 1;
    uint32_t J1 : 1;
    uint32_t _11 : 2;
    uint32_t imm10H : 10;
    uint32_t S : 1;
    uint32_t _11110  : 5;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(BLXT2_32) == 4, " ");

// Branches and miscellaneous control
union BranchesMiscControl32 {
  uint32_t flat;
  struct {
    uint32_t _11110  : 5;
    uint32_t op0 : 1;
    uint32_t op1 : 4;
    uint32_t op2 : 2;
    uint32_t _19_to_16 : 4;
    uint32_t _1 : 1;
    uint32_t op3 : 3;
    uint32_t _b11 : 1;
    uint32_t op4 : 3;
    uint32_t _7_to_6 : 2;
    uint32_t op5 : 1;
    uint32_t _4_to_0 : 5;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(BranchesMiscControl32) == 4, " ");

// 32-bit instructions
union Top32bit {
  uint32_t flat;
  struct {
    uint32_t _14_to_0 : 15;
    uint32_t op3 : 1;
    uint32_t _19_to_16 : 4;
    uint32_t op1 : 5;
    uint32_t op0 : 4;
    uint32_t _111  : 3;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(Top32bit) == 4, " ");

// ------------- 16 Bit Instructions -------------

static const char *const kIdpNamesAddSubLowReg[] = {
    [0b0] = "ADDL_T2",  [0b1] = "SUBL_T2"
};

//  S
//  0 ADD, ADDS (register)
//  1 SUB, SUBS (register)
// Add, subtract (three low registers)
static bool TryDecode16AddSub3LowReg(Instruction &inst, uint16_t bits) {

  // TODO(sonya) ADDS, SUBS - Decide how to handle InITBlock()

  const AddSub3LowReg16 enc = {bits};
  inst.category = Instruction::kCategoryNormal;
  inst.function = kIdpNamesAddSubLowReg[enc.S];


  // Unconditionally executed
  AddIntRegOp(inst, uint32_t(enc.Rd), 32u, Operand::kActionWrite);
  AddIntRegOp(inst, uint32_t(enc.Rn), 32u, Operand::kActionRead);
  AddIntRegOp(inst, uint32_t(enc.Rm), 32u, Operand::kActionRead);

  return true;

}

//  S
//  0 ADD, ADDS (immediate)
//  1 SUB, SUBS (immediate)
// Add, subtract (two low registers and immediate)
static bool TryDecode16AddSub2LowRegImm(Instruction &inst, uint16_t bits) {

  // TODO(sonya) ADDS, SUBS - Decide how to handle InITBlock()

  const AddSub2LowRegImm16 enc = {bits};
  inst.category = Instruction::kCategoryNormal;
  inst.function = kIdpNamesAddSubLowReg[enc.S];

  // Unconditionally executed
  AddIntRegOp(inst, uint32_t(enc.Rd), 32u, Operand::kActionWrite);
  AddIntRegOp(inst, uint32_t(enc.Rn), 32u, Operand::kActionRead);
  AddImmOp(inst, uint32_t(enc.imm3));

  return true;

}

static const char *const kIdpAddSubComp1LowRegImm[] = {
    [0b00] = "MOVL_T2",  [0b01] = "CMPL_T2",
    [0b10] = "ADDL_T2",  [0b11] = "SUBL_T2"
};


//  op
//  00  MOV, MOVS (immediate)
//  01  CMP (immediate)
//  10  ADD, ADDS (immediate)
//  11  SUB, SUBS (immediate)
// Add, subtract, compare, move (one low register and immediate) TODO(sonya)
static bool TryDecode16AddSubComp1LowRegImm(Instruction &inst, uint16_t bits) {

  // TODO(sonya):  setflags = !InITBlock()

  const AddSubComp1LowRegImm16 enc = {bits};
  inst.category = Instruction::kCategoryNormal;
  inst.function = kIdpAddSubComp1LowRegImm[enc.op];

  // Unconditionally executed
  AddIntRegOp(inst, uint32_t(enc.Rd), 32u, Operand::kActionWrite);
  if (enc.op) {
    AddIntRegOp(inst, uint32_t(enc.Rd), 32u, Operand::kActionRead);
  }
  AddImmOp(inst, uint32_t(enc.imm8));

  return true;

}

// MOV, MOVS (register) — T2 TODO(sonya)
static bool TryDecode16MOVrT2(Instruction &inst, uint16_t bits) {
  inst.category = Instruction::kCategoryError;
  return false;

//  const MOVrT2_16 enc = {bits};
//  inst.category = Instruction::kCategoryNormal;
//  inst.function = "MOVL_T2";
//
//  return true;

}

//  B L
//  0 0 STR (immediate)
//  0 1 LDR (immediate)
//  1 0 STRB (immediate)
//  1 1 LDRB (immediate)
// Load/store word/byte (immediate offset) TODO(sonya)
static bool TryDecode16LoadStoreWordByteImm(Instruction &inst, uint16_t bits) {
  inst.category = Instruction::kCategoryError;
  return false;
//  const LoadStoreWordByteImm16 enc = {bits};
}

//  L
//  0 STR (immediate)
//  1 LDR (immediate)
// Load/store (SP-relative) TODO(sonya)
static bool TryDecode16LoadStoreSPRelative(Instruction &inst, uint16_t bits) {
  inst.category = Instruction::kCategoryError;
  return false;
//  const LoadStoreSPRelative16 enc = {bits};
}

//  SP
//  0 ADR
//  1 ADD, ADDS (SP plus immediate)
// Add PC/SP (immediate) TODO(sonya)
static bool TryDecode16AddPCSP(Instruction &inst, uint16_t bits) {

  const AddPCSPImm16 enc = {bits};
  inst.function = enc.SP ? "ADDL_T2" : "ADR";

  // TODO(sonya): ADR

  if (enc.SP) {
    inst.category = Instruction::kCategoryNormal;

    AddIntRegOp(inst, enc.Rd, 32u, Operand::kActionWrite);
    AddIntRegOp(inst, kSPRegNum, 32u, Operand::kActionRead);
    AddImmOp(inst, uint32_t(enc.imm8 << 2));

    return true;
  }

  inst.category = Instruction::kCategoryError;
  return false;
}

// CBNZ, CBZ TODO(sonya)
static bool TryDecode16CBZ(Instruction &inst, uint16_t bits) {
  inst.category = Instruction::kCategoryError;
  return false;
}


// Adjust SP (immediate)
static bool TryDecode16AdjustSPImm(Instruction &inst, uint16_t bits) {

  const AdjustSPImm16 enc = {bits};

  // TODO(sonya):  setflags = !InITBlock()

  inst.category = Instruction::kCategoryNormal;
  inst.function = kIdpNamesAddSubLowReg[enc.S];

  AddIntRegOp(inst, kSPRegNum, 32u, Operand::kActionWrite);
  AddIntRegOp(inst, kSPRegNum, 32u, Operand::kActionRead);
  AddImmOp(inst, uint32_t(enc.imm7 << 2));

  return true;
}

// B — T1 encoding TODO(sonya)
static bool TryDecode16B_T1(Instruction &inst, uint16_t bits) {
  inst.category = Instruction::kCategoryError;
  return false;
//  const B_T1_16 enc = {bits};
}

// B — T2 encoding TODO(sonya)
static bool TryDecode16B_T2(Instruction &inst, uint16_t bits) {
  inst.category = Instruction::kCategoryError;
  return false;
//  const B_T2_16 enc = {bits};
}

// ------------- 32 Bit Instructions -------------

//  opc L
//  00  0 SRS, SRSDA, SRSDB, SRSIA, SRSIB — T1
//  00  1 RFE, RFEDA, RFEDB, RFEIA, RFEIB — T1
//  01  0 STM, STMIA, STMEA
//  01  1 LDM, LDMIA, LDMFD
//  10  0 STMDB, STMFD
//  10  1 LDMDB, LDMEA
//  11  0 SRS, SRSDA, SRSDB, SRSIA, SRSIB — T2
//  11  1 RFE, RFEDA, RFEDB, RFEIA, RFEIB — T2
// Load/Store Multiple TODO(sonya)
// NOTE(sonya): this should become a template probably
// (see TryDecodeLoadStoreMultiple in aarch32. the semantics are identical)
static bool TryDecode32LoadStoreMult(Instruction &inst, uint32_t bits) {
  inst.category = Instruction::kCategoryError;
  return false;
//  const LoadStoreMult32 enc = {bits};
}

// BL, BLX (immediate) — T1 TODO(sonya)
static bool TryDecode32BL(Instruction &inst, uint32_t bits) {
  inst.category = Instruction::kCategoryError;
  return false;
//  const BLT1_32 enc = {bits};
}

// BL, BLX (immediate) — T2 TODO(sonya)
static bool TryDecode32BLX(Instruction &inst, uint32_t bits) {
  inst.category = Instruction::kCategoryError;
  return false;
//  const BLXT2_32 enc = {bits};
}

// -----------------------------------------------

//   op0   op1  op2   op3
//  0000                    Adjust SP (immediate)
//  0010                    Extend
//  0110    00   0          SETPAN  (ARMv8.1)
//  0110    00   1          UNALLOCATED
//  0110    01              Change Processor State
//  0110    1x              UNALLOCATED
//  0111                    UNALLOCATED
//  1000                    UNALLOCATED
//  1010    10              HLT
//  1010  != 10             Reverse bytes
//  1110                    BKPT
//  1111             0000   Hints
//  1111           != 0000  IT
//  x0x1                    CBNZ, CBZ
//  x10x                    Push and Pop
static TryDecode16 *TryDecodeMisc16(uint16_t bits) {
  const Misc16 enc = {bits};

  if (!enc.op0) {
    return TryDecode16AdjustSPImm;

  // op0 == x0x1    CBNZ, CBZ
  } else if ((enc.op0 & 0b0001) && !((enc.op0 << 1) >> 3)) {
    return TryDecode16CBZ;
  }

  return nullptr;
}

//    op0
//  00xxxx  Shift (immediate), add, subtract, move, and compare
//  010000  Data-processing (two low registers)
//  010001  Special data instructions and branch and exchange
//  01001x  LDR (literal) — T1
//  0101xx  Load/store (register offset)
//  011xxx  Load/store word/byte (immediate offset)
//  1000xx  Load/store halfword (immediate offset)
//  1001xx  Load/store (SP-relative)
//  1010xx  Add PC/SP (immediate)
//  1011xx  Miscellaneous 16-bit instructions
//  1100xx  Load/store multiple
//  1101xx  Conditional branch, and Supervisor Call
static TryDecode16 *Try16bit(uint16_t bits) {
  uint16_t op0 = bits >> 10;

  // The following constraints also apply to this encoding: op0<5:3> != 111
  if ((op0 >> 3) == 0b111) {
    return nullptr;
  }

  // 00xxxx  Shift (immediate), add, subtract, move, and compare
  if (!(op0 >> 4)) {

    // op0   op1   op2
    //  0     11    0   Add, subtract (three low registers)
    //  0     11    1   Add, subtract (two low registers and immediate)
    //  0   != 11       MOV, MOVS (register) — T2
    //  1               Add, subtract, compare, move (one low register and
    //                  immediate)
    const ShiftImmAddSubMoveComp16 enc = {bits};

    if (enc.op0) {
      return TryDecode16AddSubComp1LowRegImm;

    } else if (enc.op1 != 0b11) {
      return TryDecode16MOVrT2;

    } else if (enc.op2) {
      return TryDecode16AddSub2LowRegImm;

    } else {
      return TryDecode16AddSub3LowReg;

    }
  // 010001  Special data instructions and branch and exchange
  } else if (op0 == 0b010001) {
    // TODO(sonya): Add, subtract, compare, move (two high registers)
    // -- for ADD, ADDS (register)
    return nullptr;

  // 011xxx  Load/store word/byte (immediate offset)
  } else if ((op0 >> 3) == 0b011) {
    return TryDecode16LoadStoreWordByteImm;

  // 1001xx  Load/store (SP-relative)
  } else if ((op0 >> 2) == 0b1001) {
    return TryDecode16LoadStoreSPRelative;

  // 1010xx  Add PC/SP (immediate)
  } else if ((op0 >> 2) == 0b1010) {
    return TryDecode16AddPCSP;

  // 1011xx  Miscellaneous 16-bit instructions
  } else if ((op0 >> 2) == 0b1011) {
    return TryDecodeMisc16(bits);

  // 1101xx  Conditional branch, and Supervisor Call
  } else if ((op0 >> 2) == 0b1101) {
    uint16_t _op0 = (bits << 4) >> 9;

    //   op0
    //  111x      Exception generation
    // != 111x    B — T1
    if (_op0 == 0b111) {
      return nullptr;
    } else {
      return TryDecode16B_T1;
    }
  }

  return nullptr;
}

//  op0    op1  op2 op3   op4 op5
//   0    1110  0x  0x0        0  MSR (register)
//   0    1110  0x  0x0        1  MSR (Banked register)
//   0    1110  10  0x0   000     Hints
//   0    1110  10  0x0 != 000    Change processor state
//   0    1110  11  0x0           Miscellaneous system
//   0    1111  00  0x0           BXJ
//   0    1111  01  0x0           Exception return
//   0    1111  1x  0x0        0  MRS
//   0    1111  1x  0x0        1  MRS (Banked register)
//   1    1110  00  000           DCPS
//   1    1110  00  010           UNALLOCATED
//   1    1110  01  0x0           UNALLOCATED
//   1    1110  1x  0x0           UNALLOCATED
//   1    1111  0x  0x0           UNALLOCATED
//   1    1111  1x  0x0           Exception generation
//      != 111x     0x0           B — T3
//                  0x1           B — T4
//                  1x0           BL, BLX (immediate) — T2
//                  1x1           BL, BLX (immediate) — T1
// Branches and miscellaneous control
static TryDecode *TryBranchesMiscControl32(uint32_t bits) {
  const BranchesMiscControl32 enc = {bits};

  if (enc.op3 >> 2) { // op3 == 1xx
    if (enc.op3 & 0b001) { // op3 == 1x1
      return TryDecode32BL;

    } else { // // op3 == 1x0
      return TryDecode32BLX;

    }
  }

  return nullptr;
}


//   op0    op1    op3
//  x11x                  System register access, Advanced SIMD, and
//                        floating-point
//  0100   xx0xx          Load/store multiple
//  0100   xx1xx          Load/store dual, load/store exclusive,
//                        load-acquire/store-release, and table branch
//  0101                  Data-processing (shifted register)
//  10xx            1     Branches and miscellaneous control
//  10x0            0     Data-processing (modified immediate)
//  10x1            0     Data-processing (plain binary immediate)
//  1100   1xxx0          Advanced SIMD element or structure load/store
//  1100  != 1xxx0        Load/store single
//  1101   0xxxx          Data-processing (register)
//  1101   10xxx          Multiply, multiply accumulate, and absolute difference
//  1101   11xxx          Long multiply and divide
static TryDecode *Try32Bit(uint32_t bits) {
  const Top32bit enc = {bits};

  // op0 == 0100, op1 == xx0xx, Load/store multiple
  if ((enc.op0 == 0b0100) && !(enc.op1 & 0b00100)) {
    return TryDecode32LoadStoreMult;

  // op0 == 10xx, op3 == 1, Branches and miscellaneous control
  } else if (((enc.op0 >> 2) == 0b10) && enc.op3){
    return TryBranchesMiscControl32(bits);

  }

  return nullptr;
}

bool DecodeThumb2Instruction(Instruction &inst, uint32_t bits) {
  bool ret;

  //  op0     op1
  // != 111         16-bit
  //  111      00   B — T2
  //  111    != 00  32-bit
  // TODO(sonya): make adjustments to inst for a 16 bit increment
  {
    auto bits16 = uint16_t(bits >> 16);

    // 16-bit instructions
    if (bits >> 13 != 0b111) {
      inst.next_pc = inst.pc + 2ull;  // Default fall-through.
      //inst.bytes = inst_bytes;

      auto decoder = Try16bit(bits16);
      if (!decoder) {
        LOG(ERROR) << "unhandled bits " << std::hex << bits << std::dec;
        LOG(ERROR) << "unhandled bits16 " << std::hex << bits16 << std::dec;
        return false;
      }
      ret = decoder(inst, bits16);

    // B — T2
    } else if (!((bits << 3) >> 11)) {
      inst.next_pc = inst.pc + 2ull;  // Default fall-through.
      //inst.bytes = inst_bytes;

      auto decoder = TryDecode16B_T2;
      ret = decoder(inst, bits16);

    // 32-bit instructions
    } else {
      auto decoder = Try32Bit(bits);

      if (!decoder) {
        LOG(ERROR) << "unhandled bits " << std::hex << bits << std::dec;
        return false;
      }

      ret = decoder(inst, bits);

    }
  }

  LOG(ERROR) << inst.Serialize();
  return ret;
}
} // namespace

}  // namespace remill


