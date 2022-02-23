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

typedef std::optional<uint32_t>(InstEval)(uint32_t, uint32_t);

//bool DecodeCondition(Instruction &inst, uint32_t cond);

void AddIntRegOp(Instruction &inst, unsigned index, unsigned size,
                        Operand::Action action);

void AddIntRegOp(Instruction &inst, const char *reg_name, unsigned size,
                        Operand::Action action);

void AddImmOp(Instruction &inst, uint64_t value, unsigned size = 32,
                        bool is_signed = false);

}
}

