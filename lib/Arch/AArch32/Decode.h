/*
 * Decode.h
 *
 *  Created on: Feb 15, 2022
 *      Author: sonyaschriner
 */

#pragma once

#include <cstdint>

namespace remill {

class Instruction;

namespace aarch32 {

bool DecodeThumb2Instruction(Instruction &inst, uint32_t bits);

typedef bool(TryDecode)(Instruction &, uint32_t);
typedef bool(TryDecode16)(Instruction &, uint16_t);

static constexpr auto kPCRegNum = 15u;
static constexpr auto kLRRegNum = 14u;
static constexpr auto kSPRegNum = 13u;

static const char *const kIntRegName[] = {
    "R0", "R1", "R2",  "R3",  "R4",  "R5",  "R6",  "R7",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"};

typedef std::optional<uint32_t>(InstEval)(uint32_t, uint32_t);

//bool DecodeCondition(Instruction &inst, uint32_t cond);

void AddIntRegOp(Instruction &inst, unsigned index, unsigned size,
                        Operand::Action action);

void AddIntRegOp(Instruction &inst, const char *reg_name, unsigned size,
                        Operand::Action action);

void AddAddrRegOp(Instruction &inst, const char *reg_name, unsigned mem_size,
                         Operand::Action mem_action,
                         unsigned disp, unsigned scale = 0);

void AddImmOp(Instruction &inst, uint64_t value, unsigned size = 32,
                        bool is_signed = false);

void AddShiftRegImmOperand(Instruction &inst, uint32_t reg_num,
                                  uint32_t shift_type, uint32_t shift_size,
                                  bool carry_out, bool can_shift_right_by_32);


}
}

