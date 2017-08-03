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

#include <cstddef>
#include <cstdio>

#define ADDRESS_SIZE_BITS 64

#include "remill/Arch/AArch64/Runtime/State.h"

int main(void) {

  printf("/* Auto-generated file! Don't modify! */\n\n");

  // X30 - State *

  // General purpose regs (except x30, which contains State *).
  printf("str x0, [x30, #%lu]\n", offsetof(State, gpr.x0));
  printf("str x1, [x30, #%lu]\n", offsetof(State, gpr.x1));
  printf("str x2, [x30, #%lu]\n", offsetof(State, gpr.x2));
  printf("str x3, [x30, #%lu]\n", offsetof(State, gpr.x3));
  printf("str x4, [x30, #%lu]\n", offsetof(State, gpr.x4));
  printf("str x5, [x30, #%lu]\n", offsetof(State, gpr.x5));
  printf("str x6, [x30, #%lu]\n", offsetof(State, gpr.x6));
  printf("str x7, [x30, #%lu]\n", offsetof(State, gpr.x7));
  printf("str x8, [x30, #%lu]\n", offsetof(State, gpr.x8));
  printf("str x9, [x30, #%lu]\n", offsetof(State, gpr.x9));
  printf("str x10, [x30, #%lu]\n", offsetof(State, gpr.x10));
  printf("str x11, [x30, #%lu]\n", offsetof(State, gpr.x11));
  printf("str x12, [x30, #%lu]\n", offsetof(State, gpr.x12));
  printf("str x13, [x30, #%lu]\n", offsetof(State, gpr.x13));
  printf("str x14, [x30, #%lu]\n", offsetof(State, gpr.x14));
  printf("str x15, [x30, #%lu]\n", offsetof(State, gpr.x15));
  printf("str x16, [x30, #%lu]\n", offsetof(State, gpr.x16));
  printf("str x17, [x30, #%lu]\n", offsetof(State, gpr.x17));
  printf("str x18, [x30, #%lu]\n", offsetof(State, gpr.x18));
  printf("str x19, [x30, #%lu]\n", offsetof(State, gpr.x19));
  printf("str x20, [x30, #%lu]\n", offsetof(State, gpr.x20));
  printf("str x21, [x30, #%lu]\n", offsetof(State, gpr.x21));
  printf("str x22, [x30, #%lu]\n", offsetof(State, gpr.x22));
  printf("str x23, [x30, #%lu]\n", offsetof(State, gpr.x23));
  printf("str x24, [x30, #%lu]\n", offsetof(State, gpr.x24));
  printf("str x25, [x30, #%lu]\n", offsetof(State, gpr.x25));
  printf("str x26, [x30, #%lu]\n", offsetof(State, gpr.x26));
  printf("str x27, [x30, #%lu]\n", offsetof(State, gpr.x27));
  printf("str x28, [x30, #%lu]\n", offsetof(State, gpr.x28));
  printf("str x29, [x30, #%lu]\n", offsetof(State, gpr.x29));

  // Save the stack pointer.
  printf("mov x29, sp\n");
  printf("str x29, [x30, #%lu]\n", offsetof(State, gpr.SP));

  printf("mov x29, #1\n");

  // Save the N flag.
  printf("strb w29, [x30, #%lu]\n", offsetof(State, sr.n));
  printf("b.mi 1f\n");
  printf("strb wzr, [x30, #%lu]\n", offsetof(State, sr.n));
  printf("1:\n");

  // Save the Z flag.
  printf("strb w29, [x30, #%lu]\n", offsetof(State, sr.z));
  printf("b.eq 1f\n");
  printf("strb wzr, [x30, #%lu]\n", offsetof(State, sr.z));
  printf("1:\n");

  // Save the C flag.
  printf("strb w29, [x30, #%lu]\n", offsetof(State, sr.c));
  printf("b.cs 1f\n");
  printf("strb wzr, [x30, #%lu]\n", offsetof(State, sr.c));
  printf("1:\n");

  // Save the V flag.
  printf("strb w29, [x30, #%lu]\n", offsetof(State, sr.v));
  printf("b.vs 1f\n");
  printf("strb wzr, [x30, #%lu]\n", offsetof(State, sr.v));
  printf("1:\n");

  // Restore x29.
  printf("ldr x29, [x30, #%lu]\n", offsetof(State, gpr.x29));

  // Save the real version of the nzvc reg.
  printf("mrs x1, nzcv\n");
  printf("str x1, [x30, #%lu]\n", offsetof(State, nzcv));

  // Floating point condition register.
  printf("mrs x1, fpcr\n");
  printf("str x1, [x30, #%lu]\n", offsetof(State, fpcr));

  // Floating point status register.
  printf("mrs x1, fpsr\n");
  printf("str x1, [x30, #%lu]\n", offsetof(State, fpsr));

  // User-space thread pointer register.
  printf("mrs x1, tpidr_el0\n");
  printf("str x1, [x30, #%lu]\n", offsetof(State, sr.tpidr_el0));

  // Secondary user space thread pointer register that is read-only from
  // user space.
  printf("mrs x1, tpidrro_el0\n");
  printf("str x1, [x30, #%lu]\n", offsetof(State, sr.tpidrro_el0));

  // Restore stolen `x1`.
  printf("ldr x1, [x30, #%lu]\n", offsetof(State, gpr.x1));

  return 0;
}
