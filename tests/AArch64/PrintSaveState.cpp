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
  printf("stp x1, x2, [x30, #%lu]\n", offsetof(State, gpr.x1));
  printf("stp x3, x4, [x30, #%lu]\n", offsetof(State, gpr.x3));
  printf("stp x5, x6, [x30, #%lu]\n", offsetof(State, gpr.x5));
  printf("stp x7, x8, [x30, #%lu]\n", offsetof(State, gpr.x7));
  printf("stp x9, x10, [x30, #%lu]\n", offsetof(State, gpr.x9));
  printf("stp x11, x12, [x30, #%lu]\n", offsetof(State, gpr.x11));
  printf("stp x13, x14, [x30, #%lu]\n", offsetof(State, gpr.x13));
  printf("stp x15, x16, [x30, #%lu]\n", offsetof(State, gpr.x15));
  printf("stp x17, x18, [x30, #%lu]\n", offsetof(State, gpr.x17));
  printf("stp x19, x20, [x30, #%lu]\n", offsetof(State, gpr.x19));
  printf("stp x21, x22, [x30, #%lu]\n", offsetof(State, gpr.x21));
  printf("stp x23, x24, [x30, #%lu]\n", offsetof(State, gpr.x23));
  printf("stp x25, x26, [x30, #%lu]\n", offsetof(State, gpr.x25));
  printf("stp x27, x28, [x30, #%lu]\n", offsetof(State, gpr.x27));
  printf("stp x29, x0, [x30, #%lu]\n", offsetof(State, gpr.x29));

  printf("str sp, [x30, #%lu]\n", offsetof(State, gpr.SP));

  // Save the N flag.
  printf("strb #1, [x30, #%lu]\n", offsetof(State, sr.n));
  printf("b.n .Ln_is_set\n");
  printf("strb xzr, [x30, #%lu]\n", offsetof(State, sr.n));
  printf(".Ln_is_set:\n");

  // Save the Z flag.
  printf("strb #1, [x30, #%lu]\n", offsetof(State, sr.z));
  printf("b.z .Lz_is_set\n");
  printf("strb xzr, [x30, #%lu]\n", offsetof(State, sr.z));
  printf(".Lz_is_set:\n");

  // Save the C flag.
  printf("strb #1, [x30, #%lu]\n", offsetof(State, sr.c));
  printf("b.c .Lc_is_set\n");
  printf("strb xzr, [x30, #%lu]\n", offsetof(State, sr.c));
  printf(".Lc_is_set:\n");

  // Save the V flag.
  printf("strb #1, [x30, #%lu]\n", offsetof(State, sr.v));
  printf("b.v .Lv_is_set\n");
  printf("strb xzr, [x30, #%lu]\n", offsetof(State, sr.v));
  printf(".Lv_is_set:\n");

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
  printf("msr x1, tpidr_el0\n");
  printf("str x1, [x30, #%lu]\n", offsetof(State, sr.tpidr_el0));

  // Secondary user space thread pointer register that is read-only from
  // user space.
  printf("msr x1, tpidrro_el0\n");
  printf("str x1, [x30, #%lu]\n", offsetof(State, sr.tpidrro_el0));

  // Restore stolen `x1`.
  printf("ldr x1, [x30, #%lu]\n", offsetof(State, gpr.x1));

  return 0;
}
