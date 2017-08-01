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

  printf("ldrb x1, [x30, #%lu]\n", offsetof(State, sr.n));
  printf("orr x2, x2, x1 LSL 31\n");

  printf("ldrb x1, [x30, #%lu]\n", offsetof(State, sr.z));
  printf("orr x2, x2, x1 LSL 30\n");

  printf("ldrb x1, [x30, #%lu]\n", offsetof(State, sr.c));
  printf("orr x2, x2, x1 LSL 29\n");

  printf("ldrb x1, [x30, #%lu]\n", offsetof(State, sr.v));
  printf("orr x2, x2, x1 LSL 28\n");

  // Sync `nzcv` between native and lifted.
  printf("str x2, [x30, #%lu]\n", offsetof(State, nzcv));
  printf("msr nzcv, x2\n");

  // Floating point condition register.
  printf("ldr x1, [x30, #%lu]\n", offsetof(State, fpcr));
  printf("msr fpcr, x1\n");

  // Floating point status register.
  printf("ldr x1, [x30, #%lu]\n", offsetof(State, fpsr));
  printf("msr fpsr, x1\n");

  // User-space thread pointer register.
  printf("ldr x1, [x30, #%lu]\n", offsetof(State, sr.tpidr_el0));
  printf("msr tpidr_el0, x1\n");

  // Secondary user space thread pointer register is read-only.

  // General purpose regs (except x30, which contains State *).
  printf("ldp x1, x2, [x30, #%lu]\n", offsetof(State, gpr.x1));
  printf("ldp x3, x4, [x30, #%lu]\n", offsetof(State, gpr.x3));
  printf("ldp x5, x6, [x30, #%lu]\n", offsetof(State, gpr.x5));
  printf("ldp x7, x8, [x30, #%lu]\n", offsetof(State, gpr.x7));
  printf("ldp x9, x10, [x30, #%lu]\n", offsetof(State, gpr.x9));
  printf("ldp x11, x12, [x30, #%lu]\n", offsetof(State, gpr.x11));
  printf("ldp x13, x14, [x30, #%lu]\n", offsetof(State, gpr.x13));
  printf("ldp x15, x16, [x30, #%lu]\n", offsetof(State, gpr.x15));
  printf("ldp x17, x18, [x30, #%lu]\n", offsetof(State, gpr.x17));
  printf("ldp x19, x20, [x30, #%lu]\n", offsetof(State, gpr.x19));
  printf("ldp x21, x22, [x30, #%lu]\n", offsetof(State, gpr.x21));
  printf("ldp x23, x24, [x30, #%lu]\n", offsetof(State, gpr.x23));
  printf("ldp x25, x26, [x30, #%lu]\n", offsetof(State, gpr.x25));
  printf("ldp x27, x28, [x30, #%lu]\n", offsetof(State, gpr.x27));
  printf("ldp x29, x0, [x30, #%lu]\n", offsetof(State, gpr.x29));

  printf("ldp sp, [x30, #%lu]\n", offsetof(State, gpr.SP));

  return 0;
}
