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
 * dildributed under the License is dildributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstddef>
#include <cstdio>

#define ADDRESS_SIZE_BITS 64

#include "remill/Arch/AArch64/Runtime/State.h"

int main(void) {

  printf("/* Auto-generated file! Don't modify! */\n\n");

  // Build up the `nzcv` bits from the `State` structure.
  printf("mov x2, #0\n");

  printf("ldrb w1, [x28, #%lu]\n", offsetof(State, sr.n));
  printf("orr x2, x2, x1, LSL 31\n");

  printf("ldrb w1, [x28, #%lu]\n", offsetof(State, sr.z));
  printf("orr x2, x2, x1, LSL 30\n");

  printf("ldrb w1, [x28, #%lu]\n", offsetof(State, sr.c));
  printf("orr x2, x2, x1, LSL 29\n");

  printf("ldrb w1, [x28, #%lu]\n", offsetof(State, sr.v));
  printf("orr x2, x2, x1, LSL 28\n");

  // Sync `nzcv` between native and lifted.
  printf("str x2, [x28, #%lu]\n", offsetof(State, nzcv));
  printf("msr nzcv, x2\n");

  // Floating point condition register.
  printf("ldr x1, [x28, #%lu]\n", offsetof(State, fpcr));

  // Floating point status register.
  printf("ldr x1, [x28, #%lu]\n", offsetof(State, fpsr));

  // Extract the cumulative invalid operation flag from the SR into the FPSR.
  printf("ldrb w2, [x28, #%lu]\n", offsetof(State, sr.ioc));
  printf("bfi x1, x2, #0, #1\n");

  // Extract the cumulative overflow flag from the SR into the FPSR.
  printf("ldrb w2, [x28, #%lu]\n", offsetof(State, sr.ofc));
  printf("bfi x1, x2, #2, #1\n");

  // Extract the cumulative underflow flag from the SR into the FPSR.
  printf("ldrb w2, [x28, #%lu]\n", offsetof(State, sr.ufc));
  printf("bfi x1, x2, #3, #1\n");

  // Extract the cumulative inexact flag from the SR into the FPSR.
  printf("ldrb w2, [x28, #%lu]\n", offsetof(State, sr.ixc));
  printf("bfi x1, x2, #4, #1\n");

  // Extract the cumulative input denormal flag from the SR into the FPSR.
  printf("ldrb w2, [x28, #%lu]\n", offsetof(State, sr.idc));
  printf("bfi x1, x2, #6, #1\n");

  // Sync `fpsr` between native and lifted.
  printf("str x1, [x28, #%lu]\n", offsetof(State, fpsr));
  printf("msr fpcr, x1\n");

  // User-space thread pointer register.
  printf("ldr x1, [x28, #%lu]\n", offsetof(State, sr.tpidr_el0));
  printf("msr tpidr_el0, x1\n");

  // Secondary user space thread pointer register is read-only.

  // SIMD regs.
  auto base = offsetof(State, simd.v[0].dqwords);
  printf("add x1, x28, #%lu\n", base);

  printf("ldur q0, [x1, #%lu]\n", offsetof(State, simd.v[0].dqwords) - base);
  printf("ldur q1, [x1, #%lu]\n", offsetof(State, simd.v[1].dqwords) - base);
  printf("ldur q2, [x1, #%lu]\n", offsetof(State, simd.v[2].dqwords) - base);
  printf("ldur q3, [x1, #%lu]\n", offsetof(State, simd.v[3].dqwords) - base);
  printf("ldur q4, [x1, #%lu]\n", offsetof(State, simd.v[4].dqwords) - base);
  printf("ldur q5, [x1, #%lu]\n", offsetof(State, simd.v[5].dqwords) - base);
  printf("ldur q6, [x1, #%lu]\n", offsetof(State, simd.v[6].dqwords) - base);
  printf("ldur q7, [x1, #%lu]\n", offsetof(State, simd.v[7].dqwords) - base);
  printf("ldur q8, [x1, #%lu]\n", offsetof(State, simd.v[8].dqwords) - base);
  printf("ldur q9, [x1, #%lu]\n", offsetof(State, simd.v[9].dqwords) - base);
  printf("ldur q10, [x1, #%lu]\n", offsetof(State, simd.v[10].dqwords) - base);
  printf("ldur q11, [x1, #%lu]\n", offsetof(State, simd.v[11].dqwords) - base);
  printf("ldur q12, [x1, #%lu]\n", offsetof(State, simd.v[12].dqwords) - base);
  printf("ldur q13, [x1, #%lu]\n", offsetof(State, simd.v[13].dqwords) - base);
  printf("ldur q14, [x1, #%lu]\n", offsetof(State, simd.v[14].dqwords) - base);
  printf("ldur q15, [x1, #%lu]\n", offsetof(State, simd.v[15].dqwords) - base);

  base = offsetof(State, simd.v[16].dqwords);
  printf("add x1, x28, #%lu\n", base);
  printf("ldur q16, [x1, #%lu]\n", offsetof(State, simd.v[16].dqwords) - base);
  printf("ldur q17, [x1, #%lu]\n", offsetof(State, simd.v[17].dqwords) - base);
  printf("ldur q18, [x1, #%lu]\n", offsetof(State, simd.v[18].dqwords) - base);
  printf("ldur q19, [x1, #%lu]\n", offsetof(State, simd.v[19].dqwords) - base);
  printf("ldur q20, [x1, #%lu]\n", offsetof(State, simd.v[20].dqwords) - base);
  printf("ldur q21, [x1, #%lu]\n", offsetof(State, simd.v[21].dqwords) - base);
  printf("ldur q22, [x1, #%lu]\n", offsetof(State, simd.v[22].dqwords) - base);
  printf("ldur q23, [x1, #%lu]\n", offsetof(State, simd.v[23].dqwords) - base);
  printf("ldur q24, [x1, #%lu]\n", offsetof(State, simd.v[24].dqwords) - base);
  printf("ldur q25, [x1, #%lu]\n", offsetof(State, simd.v[25].dqwords) - base);
  printf("ldur q26, [x1, #%lu]\n", offsetof(State, simd.v[26].dqwords) - base);
  printf("ldur q27, [x1, #%lu]\n", offsetof(State, simd.v[27].dqwords) - base);
  printf("ldur q28, [x1, #%lu]\n", offsetof(State, simd.v[28].dqwords) - base);
  printf("ldur q29, [x1, #%lu]\n", offsetof(State, simd.v[29].dqwords) - base);
  printf("ldur q30, [x1, #%lu]\n", offsetof(State, simd.v[30].dqwords) - base);
  printf("ldur q31, [x1, #%lu]\n", offsetof(State, simd.v[31].dqwords) - base);

  // General purpose regs (except x28, which contains State *).
  printf("ldr x0, [x28, #%lu]\n", offsetof(State, gpr.x0));
  printf("ldr x1, [x28, #%lu]\n", offsetof(State, gpr.x1));
  printf("ldr x2, [x28, #%lu]\n", offsetof(State, gpr.x2));
  printf("ldr x3, [x28, #%lu]\n", offsetof(State, gpr.x3));
  printf("ldr x4, [x28, #%lu]\n", offsetof(State, gpr.x4));
  printf("ldr x5, [x28, #%lu]\n", offsetof(State, gpr.x5));
  printf("ldr x6, [x28, #%lu]\n", offsetof(State, gpr.x6));
  printf("ldr x7, [x28, #%lu]\n", offsetof(State, gpr.x7));
  printf("ldr x8, [x28, #%lu]\n", offsetof(State, gpr.x8));
  printf("ldr x9, [x28, #%lu]\n", offsetof(State, gpr.x9));
  printf("ldr x10, [x28, #%lu]\n", offsetof(State, gpr.x10));
  printf("ldr x11, [x28, #%lu]\n", offsetof(State, gpr.x11));
  printf("ldr x12, [x28, #%lu]\n", offsetof(State, gpr.x12));
  printf("ldr x13, [x28, #%lu]\n", offsetof(State, gpr.x13));
  printf("ldr x14, [x28, #%lu]\n", offsetof(State, gpr.x14));
  printf("ldr x15, [x28, #%lu]\n", offsetof(State, gpr.x15));
  printf("ldr x16, [x28, #%lu]\n", offsetof(State, gpr.x16));
  printf("ldr x17, [x28, #%lu]\n", offsetof(State, gpr.x17));
  printf("ldr x18, [x28, #%lu]\n", offsetof(State, gpr.x18));
  printf("ldr x19, [x28, #%lu]\n", offsetof(State, gpr.x19));
  printf("ldr x20, [x28, #%lu]\n", offsetof(State, gpr.x20));
  printf("ldr x21, [x28, #%lu]\n", offsetof(State, gpr.x21));
  printf("ldr x22, [x28, #%lu]\n", offsetof(State, gpr.x22));
  printf("ldr x23, [x28, #%lu]\n", offsetof(State, gpr.x23));
  printf("ldr x24, [x28, #%lu]\n", offsetof(State, gpr.x24));
  printf("ldr x25, [x28, #%lu]\n", offsetof(State, gpr.x25));
  printf("ldr x26, [x28, #%lu]\n", offsetof(State, gpr.x26));
  printf("ldr x27, [x28, #%lu]\n", offsetof(State, gpr.x27));
  printf("ldr x30, [x28, #%lu]\n", offsetof(State, gpr.x30));

  // Restore the stack pointer.
  printf("ldr x29, [x28, #%lu]\n", offsetof(State, gpr.sp));
  printf("mov sp, x29\n");

  printf("ldr x29, [x28, #%lu]\n", offsetof(State, gpr.x29));

  return 0;
}
