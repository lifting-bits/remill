/*
 * Copyright (c) 2021 Trail of Bits, Inc.
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

#include "remill/Arch/Runtime/Intrinsics.h"
#include "remill/Arch/Runtime/Operators.h"
#include "remill/Arch/MSP430/Runtime/State.h"
#include "remill/Arch/MSP430/Runtime/Types.h"

#define REG_PC state.gpr.r0.word
#define REG_SP state.gpr.r1.word
#define REG_SR state.gpr.r2.word

namespace {

template <typename T>
DEF_SEM(RRC, T src_dst, R16W writeback_reg, R16 writeback_val, PC next_pc) {
  auto val = Read(src_dst);
  auto carry_in = static_cast<uint16_t>(state.nzcv.c);
  Write(writeback_reg, Read(writeback_val));
  Write(REG_PC, Read(next_pc));
  Write(src_dst, UOr(UShr(val, 1_u16), UShl(carry_in, 15_u16)));
  state.nzcv.c = !!UAnd(val, 1_u16);
  return memory;
}

DEF_SEM(RRCB_REG, R16W src_dst, R16W writeback_reg, R16 writeback_val, PC next_pc) {
  auto val = Read(src_dst);
  auto val_low = static_cast<uint8_t>(val);
  auto carry_in = static_cast<uint8_t>(state.nzcv.c);
  auto new_val_low = UOr(UShr(val_low, 1_u8), UShl(carry_in, 7_u8));
  Write(writeback_reg, Read(writeback_val));
  Write(REG_PC, Read(next_pc));
  Write(src_dst, UOr(UAnd(val, 0xFF00_u16), ZExt(new_val_low)));
  state.nzcv.c = !!UAnd(val_low, 1_u8);
  return memory;
}

DEF_SEM(RRCB_MEM, M8W src_dst, R16W writeback_reg, R16 writeback_val, PC next_pc) {
  auto val_low = static_cast<uint8_t>(Read(src_dst));
  auto carry_in = static_cast<uint8_t>(state.nzcv.c);
  Write(writeback_reg, Read(writeback_val));
  Write(REG_PC, Read(next_pc));
  Write(src_dst, UOr(UShr(val_low, 1_u8), UShl(carry_in, 7_u8)));
  state.nzcv.c = !!UAnd(val_low, 1_u8);
  return memory;
}

}  // namespace

DEF_ISEL(RRC_Rw) = RRC<R16W>;
DEF_ISEL(RRC_M16w) = RRC<M16W>;

DEF_ISEL(RRCB_Rw) = RRCB_REG;
DEF_ISEL(RRCB_M8w) = RRCB_MEM;
