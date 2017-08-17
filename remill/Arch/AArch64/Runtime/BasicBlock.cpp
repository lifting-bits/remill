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
[[gnu::used]] Memory *__remill_basic_block(State &state, addr_t curr_pc,
                                           Memory *memory) {
  bool branch_taken = false;

  // Note: These variables MUST be defined for all architectures.
  auto &STATE = state;
  auto &MEMORY = *memory;
  auto &PC = state.gpr.pc.qword;
  auto &BRANCH_TAKEN = branch_taken;

  // `PC` should already have the correct value, but it's nice to make sure
  // that `curr_pc` is used throughout, as it helps with certain downstream
  // uses to be able to depend on the optimizer not eliminating `curr_pc`.
  PC = curr_pc;
  auto &WPC = state.gpr.pc.dword;

  auto &W0 = state.gpr.x0.dword;
  auto &W1 = state.gpr.x1.dword;
  auto &W2 = state.gpr.x2.dword;
  auto &W3 = state.gpr.x3.dword;

  auto &W4 = state.gpr.x4.dword;
  auto &W5 = state.gpr.x5.dword;
  auto &W6 = state.gpr.x6.dword;
  auto &W7 = state.gpr.x7.dword;

  auto &W8 = state.gpr.x8.dword;
  auto &W9 = state.gpr.x9.dword;
  auto &W10 = state.gpr.x10.dword;
  auto &W11 = state.gpr.x11.dword;

  auto &W12 = state.gpr.x12.dword;
  auto &W13 = state.gpr.x13.dword;
  auto &W14 = state.gpr.x14.dword;
  auto &W15 = state.gpr.x15.dword;

  auto &W16 = state.gpr.x16.dword;
  auto &W17 = state.gpr.x17.dword;
  auto &W18 = state.gpr.x18.dword;
  auto &W19 = state.gpr.x19.dword;

  auto &W20 = state.gpr.x20.dword;
  auto &W21 = state.gpr.x21.dword;
  auto &W22 = state.gpr.x22.dword;
  auto &W23 = state.gpr.x23.dword;

  auto &W24 = state.gpr.x24.dword;
  auto &W25 = state.gpr.x25.dword;
  auto &W26 = state.gpr.x26.dword;
  auto &W27 = state.gpr.x27.dword;

  auto &W28 = state.gpr.x28.dword;
  auto &W29 = state.gpr.x29.dword;
  auto &W30 = state.gpr.x30.dword;

  auto &X0 = state.gpr.x0.qword;
  auto &X1 = state.gpr.x1.qword;
  auto &X2 = state.gpr.x2.qword;
  auto &X3 = state.gpr.x2.qword;

  auto &X4 = state.gpr.x4.qword;
  auto &X5 = state.gpr.x5.qword;
  auto &X6 = state.gpr.x6.qword;
  auto &X7 = state.gpr.x7.qword;

  auto &X8 = state.gpr.x8.qword;
  auto &X9 = state.gpr.x9.qword;
  auto &X10 = state.gpr.x10.qword;
  auto &X11 = state.gpr.x11.qword;

  auto &X12 = state.gpr.x12.qword;
  auto &X13 = state.gpr.x13.qword;
  auto &X14 = state.gpr.x14.qword;
  auto &X15 = state.gpr.x15.qword;

  auto &X16 = state.gpr.x16.qword;
  auto &X17 = state.gpr.x17.qword;
  auto &X18 = state.gpr.x18.qword;
  auto &X19 = state.gpr.x19.qword;

  auto &X20 = state.gpr.x20.qword;
  auto &X21 = state.gpr.x21.qword;
  auto &X22 = state.gpr.x22.qword;
  auto &X23 = state.gpr.x23.qword;

  auto &X24 = state.gpr.x24.qword;
  auto &X25 = state.gpr.x25.qword;
  auto &X26 = state.gpr.x26.qword;
  auto &X27 = state.gpr.x27.qword;

  auto &X28 = state.gpr.x28.qword;
  auto &X29 = state.gpr.x29.qword;
  auto &X30 = state.gpr.x30.qword;

  auto &FP = state.gpr.x29.qword;
  auto &WFP = state.gpr.x29.qword;

  auto &LP = state.gpr.x30.qword;
  auto &WLP = state.gpr.x30.qword;

  auto &SP = state.gpr.sp.qword;
  auto &WSP = state.gpr.sp.dword;

  addr_t zero = 0;
  auto &WZR = reinterpret_cast<uint32_t &>(zero);
  auto &XZR = zero;

  addr_t ignored = 0;
  auto &IGNORE_WRITE_TO_WZR = reinterpret_cast<uint32_t &>(ignored);
  auto &IGNORE_WRITE_TO_XZR = ignored;

  auto &B0 = state.simd.v[0].bytes.elems[0];
  auto &B1 = state.simd.v[1].bytes.elems[0];
  auto &B2 = state.simd.v[2].bytes.elems[0];
  auto &B3 = state.simd.v[3].bytes.elems[0];
  auto &B4 = state.simd.v[4].bytes.elems[0];
  auto &B5 = state.simd.v[5].bytes.elems[0];
  auto &B6 = state.simd.v[6].bytes.elems[0];
  auto &B7 = state.simd.v[7].bytes.elems[0];
  auto &B8 = state.simd.v[8].bytes.elems[0];
  auto &B9 = state.simd.v[9].bytes.elems[0];
  auto &B10 = state.simd.v[10].bytes.elems[0];
  auto &B11 = state.simd.v[11].bytes.elems[0];
  auto &B12 = state.simd.v[12].bytes.elems[0];
  auto &B13 = state.simd.v[13].bytes.elems[0];
  auto &B14 = state.simd.v[14].bytes.elems[0];
  auto &B15 = state.simd.v[15].bytes.elems[0];
  auto &B16 = state.simd.v[16].bytes.elems[0];
  auto &B17 = state.simd.v[17].bytes.elems[0];
  auto &B18 = state.simd.v[18].bytes.elems[0];
  auto &B19 = state.simd.v[19].bytes.elems[0];
  auto &B20 = state.simd.v[20].bytes.elems[0];
  auto &B21 = state.simd.v[21].bytes.elems[0];
  auto &B22 = state.simd.v[22].bytes.elems[0];
  auto &B23 = state.simd.v[23].bytes.elems[0];
  auto &B24 = state.simd.v[24].bytes.elems[0];
  auto &B25 = state.simd.v[25].bytes.elems[0];
  auto &B26 = state.simd.v[26].bytes.elems[0];
  auto &B27 = state.simd.v[27].bytes.elems[0];
  auto &B28 = state.simd.v[28].bytes.elems[0];
  auto &B29 = state.simd.v[29].bytes.elems[0];
  auto &B30 = state.simd.v[30].bytes.elems[0];
  auto &B31 = state.simd.v[31].bytes.elems[0];

  // TODO(pag): Add half words here.

  auto &S0 = state.simd.v[0].floats.elems[0];
  auto &S1 = state.simd.v[1].floats.elems[0];
  auto &S2 = state.simd.v[2].floats.elems[0];
  auto &S3 = state.simd.v[3].floats.elems[0];
  auto &S4 = state.simd.v[4].floats.elems[0];
  auto &S5 = state.simd.v[5].floats.elems[0];
  auto &S6 = state.simd.v[6].floats.elems[0];
  auto &S7 = state.simd.v[7].floats.elems[0];
  auto &S8 = state.simd.v[8].floats.elems[0];
  auto &S9 = state.simd.v[9].floats.elems[0];
  auto &S10 = state.simd.v[10].floats.elems[0];
  auto &S11 = state.simd.v[11].floats.elems[0];
  auto &S12 = state.simd.v[12].floats.elems[0];
  auto &S13 = state.simd.v[13].floats.elems[0];
  auto &S14 = state.simd.v[14].floats.elems[0];
  auto &S15 = state.simd.v[15].floats.elems[0];
  auto &S16 = state.simd.v[16].floats.elems[0];
  auto &S17 = state.simd.v[17].floats.elems[0];
  auto &S18 = state.simd.v[18].floats.elems[0];
  auto &S19 = state.simd.v[19].floats.elems[0];
  auto &S20 = state.simd.v[20].floats.elems[0];
  auto &S21 = state.simd.v[21].floats.elems[0];
  auto &S22 = state.simd.v[22].floats.elems[0];
  auto &S23 = state.simd.v[23].floats.elems[0];
  auto &S24 = state.simd.v[24].floats.elems[0];
  auto &S25 = state.simd.v[25].floats.elems[0];
  auto &S26 = state.simd.v[26].floats.elems[0];
  auto &S27 = state.simd.v[27].floats.elems[0];
  auto &S28 = state.simd.v[28].floats.elems[0];
  auto &S29 = state.simd.v[29].floats.elems[0];
  auto &S30 = state.simd.v[30].floats.elems[0];
  auto &S31 = state.simd.v[31].floats.elems[0];

  auto &D0 = state.simd.v[0].doubles.elems[0];
  auto &D1 = state.simd.v[1].doubles.elems[0];
  auto &D2 = state.simd.v[2].doubles.elems[0];
  auto &D3 = state.simd.v[3].doubles.elems[0];
  auto &D4 = state.simd.v[4].doubles.elems[0];
  auto &D5 = state.simd.v[5].doubles.elems[0];
  auto &D6 = state.simd.v[6].doubles.elems[0];
  auto &D7 = state.simd.v[7].doubles.elems[0];
  auto &D8 = state.simd.v[8].doubles.elems[0];
  auto &D9 = state.simd.v[9].doubles.elems[0];
  auto &D10 = state.simd.v[10].doubles.elems[0];
  auto &D11 = state.simd.v[11].doubles.elems[0];
  auto &D12 = state.simd.v[12].doubles.elems[0];
  auto &D13 = state.simd.v[13].doubles.elems[0];
  auto &D14 = state.simd.v[14].doubles.elems[0];
  auto &D15 = state.simd.v[15].doubles.elems[0];
  auto &D16 = state.simd.v[16].doubles.elems[0];
  auto &D17 = state.simd.v[17].doubles.elems[0];
  auto &D18 = state.simd.v[18].doubles.elems[0];
  auto &D19 = state.simd.v[19].doubles.elems[0];
  auto &D20 = state.simd.v[20].doubles.elems[0];
  auto &D21 = state.simd.v[21].doubles.elems[0];
  auto &D22 = state.simd.v[22].doubles.elems[0];
  auto &D23 = state.simd.v[23].doubles.elems[0];
  auto &D24 = state.simd.v[24].doubles.elems[0];
  auto &D25 = state.simd.v[25].doubles.elems[0];
  auto &D26 = state.simd.v[26].doubles.elems[0];
  auto &D27 = state.simd.v[27].doubles.elems[0];
  auto &D28 = state.simd.v[28].doubles.elems[0];
  auto &D29 = state.simd.v[29].doubles.elems[0];
  auto &D30 = state.simd.v[30].doubles.elems[0];
  auto &D31 = state.simd.v[31].doubles.elems[0];

  auto &V0 = state.simd.v[0];
  auto &V1 = state.simd.v[1];
  auto &V2 = state.simd.v[2];
  auto &V3 = state.simd.v[3];
  auto &V4 = state.simd.v[4];
  auto &V5 = state.simd.v[5];
  auto &V6 = state.simd.v[6];
  auto &V7 = state.simd.v[7];
  auto &V8 = state.simd.v[8];
  auto &V9 = state.simd.v[9];
  auto &V10 = state.simd.v[10];
  auto &V11 = state.simd.v[11];
  auto &V12 = state.simd.v[12];
  auto &V13 = state.simd.v[13];
  auto &V14 = state.simd.v[14];
  auto &V15 = state.simd.v[15];
  auto &V16 = state.simd.v[16];
  auto &V17 = state.simd.v[17];
  auto &V18 = state.simd.v[18];
  auto &V19 = state.simd.v[19];
  auto &V20 = state.simd.v[20];
  auto &V21 = state.simd.v[21];
  auto &V22 = state.simd.v[22];
  auto &V23 = state.simd.v[23];
  auto &V24 = state.simd.v[24];
  auto &V25 = state.simd.v[25];
  auto &V26 = state.simd.v[26];
  auto &V27 = state.simd.v[27];
  auto &V28 = state.simd.v[28];
  auto &V29 = state.simd.v[29];
  auto &V30 = state.simd.v[30];
  auto &V31 = state.simd.v[31];

  auto &TPIDR_EL0 = state.sr.tpidr_el0;
  auto &TPIDRRO_EL0 = state.sr.tpidrro_el0;

  // Lifted code will be placed here in clones versions of this function.
  return memory;
}

#pragma clang diagnostic pop

}  // extern C

#include "remill/Arch/Runtime/Intrinsics.cpp"
