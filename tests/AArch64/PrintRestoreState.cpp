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

  printf("ldrb w1, [x30, #%lu]\n", offsetof(State, sr.n));
  printf("orr x2, x2, x1, LSL 31\n");

  printf("ldrb w1, [x30, #%lu]\n", offsetof(State, sr.z));
  printf("orr x2, x2, x1, LSL 30\n");

  printf("ldrb w1, [x30, #%lu]\n", offsetof(State, sr.c));
  printf("orr x2, x2, x1, LSL 29\n");

  printf("ldrb w1, [x30, #%lu]\n", offsetof(State, sr.v));
  printf("orr x2, x2, x1, LSL 28\n");

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
  printf("ldr x0, [x30, #%lu]\n", offsetof(State, gpr.x0));
  printf("ldr x1, [x30, #%lu]\n", offsetof(State, gpr.x1));
  printf("ldr x2, [x30, #%lu]\n", offsetof(State, gpr.x2));
  printf("ldr x3, [x30, #%lu]\n", offsetof(State, gpr.x3));
  printf("ldr x4, [x30, #%lu]\n", offsetof(State, gpr.x4));
  printf("ldr x5, [x30, #%lu]\n", offsetof(State, gpr.x5));
  printf("ldr x6, [x30, #%lu]\n", offsetof(State, gpr.x6));
  printf("ldr x7, [x30, #%lu]\n", offsetof(State, gpr.x7));
  printf("ldr x8, [x30, #%lu]\n", offsetof(State, gpr.x8));
  printf("ldr x9, [x30, #%lu]\n", offsetof(State, gpr.x9));
  printf("ldr x10, [x30, #%lu]\n", offsetof(State, gpr.x10));
  printf("ldr x11, [x30, #%lu]\n", offsetof(State, gpr.x11));
  printf("ldr x12, [x30, #%lu]\n", offsetof(State, gpr.x12));
  printf("ldr x13, [x30, #%lu]\n", offsetof(State, gpr.x13));
  printf("ldr x14, [x30, #%lu]\n", offsetof(State, gpr.x14));
  printf("ldr x15, [x30, #%lu]\n", offsetof(State, gpr.x15));
  printf("ldr x16, [x30, #%lu]\n", offsetof(State, gpr.x16));
  printf("ldr x17, [x30, #%lu]\n", offsetof(State, gpr.x17));
  printf("ldr x18, [x30, #%lu]\n", offsetof(State, gpr.x18));
  printf("ldr x19, [x30, #%lu]\n", offsetof(State, gpr.x19));
  printf("ldr x20, [x30, #%lu]\n", offsetof(State, gpr.x20));
  printf("ldr x21, [x30, #%lu]\n", offsetof(State, gpr.x21));
  printf("ldr x22, [x30, #%lu]\n", offsetof(State, gpr.x22));
  printf("ldr x23, [x30, #%lu]\n", offsetof(State, gpr.x23));
  printf("ldr x24, [x30, #%lu]\n", offsetof(State, gpr.x24));
  printf("ldr x25, [x30, #%lu]\n", offsetof(State, gpr.x25));
  printf("ldr x26, [x30, #%lu]\n", offsetof(State, gpr.x26));
  printf("ldr x27, [x30, #%lu]\n", offsetof(State, gpr.x27));
  printf("ldr x28, [x30, #%lu]\n", offsetof(State, gpr.x28));

  // Restore the stack pointer.
  printf("ldr x29, [x30, #%lu]\n", offsetof(State, gpr.SP));
  printf("mov sp, x29\n");

  printf("ldr x29, [x30, #%lu]\n", offsetof(State, gpr.x29));

  return 0;
}
