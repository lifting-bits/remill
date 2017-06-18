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

#include "remill/Arch/AArch64/Runtime/State.h"

extern "C" {

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-variable"

// Instructions will be lifted into clones of this function.
[[gnu::used]] Memory *__remill_basic_block(Memory *memory, State &state,
                                           addr_t curr_pc) {
  bool branch_taken = false;

  // Note: These variables MUST be defined for all architectures.
  auto &STATE = state;
  auto &MEMORY = *memory;
  auto &PC = state.gpr.PC.qword;
  auto &BRANCH_TAKEN = branch_taken;

  // `PC` should already have the correct value, but it's nice to make sure
  // that `curr_pc` is used throughout, as it helps with certain downstream
  // uses to be able to depend on the optimizer not eliminating `curr_pc`.
  PC = curr_pc;
  auto &WPC = state.gpr.PC.dword;

  auto &W0 = state.gpr.X0.dword;
  auto &W1 = state.gpr.X1.dword;
  auto &W2 = state.gpr.X2.dword;
  auto &W3 = state.gpr.X3.dword;

  auto &W4 = state.gpr.X4.dword;
  auto &W5 = state.gpr.X5.dword;
  auto &W6 = state.gpr.X6.dword;
  auto &W7 = state.gpr.X7.dword;

  auto &W8 = state.gpr.X8.dword;
  auto &W9 = state.gpr.X9.dword;
  auto &W10 = state.gpr.X10.dword;
  auto &W11 = state.gpr.X11.dword;

  auto &W12 = state.gpr.X12.dword;
  auto &W13 = state.gpr.X13.dword;
  auto &W14 = state.gpr.X14.dword;
  auto &W15 = state.gpr.X15.dword;

  auto &W16 = state.gpr.X16.dword;
  auto &W17 = state.gpr.X17.dword;
  auto &W18 = state.gpr.X18.dword;
  auto &W19 = state.gpr.X19.dword;

  auto &W20 = state.gpr.X20.dword;
  auto &W21 = state.gpr.X21.dword;
  auto &W22 = state.gpr.X22.dword;
  auto &W23 = state.gpr.X23.dword;

  auto &W24 = state.gpr.X24.dword;
  auto &W25 = state.gpr.X25.dword;
  auto &W26 = state.gpr.X26.dword;
  auto &W27 = state.gpr.X27.dword;

  auto &W28 = state.gpr.X28.dword;
  auto &W29 = state.gpr.X29.dword;
  auto &W30 = state.gpr.X30.dword;

  auto &X0 = state.gpr.X0.qword;
  auto &X1 = state.gpr.X1.qword;
  auto &X2 = state.gpr.X2.qword;
  auto &X3 = state.gpr.X2.qword;

  auto &X4 = state.gpr.X4.qword;
  auto &X5 = state.gpr.X5.qword;
  auto &X6 = state.gpr.X6.qword;
  auto &X7 = state.gpr.X7.qword;

  auto &X8 = state.gpr.X8.qword;
  auto &X9 = state.gpr.X9.qword;
  auto &X10 = state.gpr.X10.qword;
  auto &X11 = state.gpr.X11.qword;

  auto &X12 = state.gpr.X12.qword;
  auto &X13 = state.gpr.X13.qword;
  auto &X14 = state.gpr.X14.qword;
  auto &X15 = state.gpr.X15.qword;

  auto &X16 = state.gpr.X16.qword;
  auto &X17 = state.gpr.X17.qword;
  auto &X18 = state.gpr.X18.qword;
  auto &X19 = state.gpr.X19.qword;

  auto &X20 = state.gpr.X20.qword;
  auto &X21 = state.gpr.X21.qword;
  auto &X22 = state.gpr.X22.qword;
  auto &X23 = state.gpr.X23.qword;

  auto &X24 = state.gpr.X24.qword;
  auto &X25 = state.gpr.X25.qword;
  auto &X26 = state.gpr.X26.qword;
  auto &X27 = state.gpr.X27.qword;

  auto &X28 = state.gpr.X28.qword;
  auto &X29 = state.gpr.X29.qword;
  auto &X30 = state.gpr.X30.qword;

  auto &FP = state.gpr.X29.qword;
  auto &WFP = state.gpr.X29.qword;

  auto &LP = state.gpr.X30.qword;
  auto &WLP = state.gpr.X30.qword;

  auto &SP = state.gpr.X31.qword;
  auto &WSP = state.gpr.X31.dword;

  addr_t zero = 0;
  auto &WZR = reinterpret_cast<uint32_t &>(zero);
  auto &XZR = zero;

  addr_t ignored = 0;
  auto &IGNORE_WRITE_TO_WZR = reinterpret_cast<uint32_t &>(ignored);
  auto &IGNORE_WRITE_TO_XZR = ignored;

  // Lifted code will be placed here in clones versions of this function.
  return memory;
}

#pragma clang diagnostic pop

}  // extern C

#include "remill/Arch/Runtime/Intrinsics.cpp"
