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

#pragma once

#pragma clang diagnostic push
#pragma clang diagnostic fatal "-Wpadded"

#include "remill/Arch/Runtime/State.h"
#include "remill/Arch/Runtime/Types.h"

struct Reg final {
  alignas(4) uint32_t dword;
} __attribute__((packed));

static_assert(sizeof(uint32_t) == sizeof(Reg), "Invalid packing of `Reg`.");
static_assert(0 == __builtin_offsetof(Reg, dword),
              "Invalid packing of `Reg::dword`.");

struct alignas(8) GPR final {

  // Prevents LLVM from casting a `GPR` into an `i64` to access `X0`.
  volatile uint32_t _0;
  Reg r0;
  volatile uint32_t _1;
  Reg r1;
  volatile uint32_t _2;
  Reg r2;
  volatile uint32_t _3;
  Reg r3;
  volatile uint32_t _4;
  Reg r4;
  volatile uint32_t _5;
  Reg r5;
  volatile uint32_t _6;
  Reg r6;
  volatile uint32_t _7;
  Reg r7;
  volatile uint32_t _8;
  Reg r8;
  volatile uint32_t _9;
  Reg r9;
  volatile uint32_t _10;
  Reg r10;
  volatile uint32_t _11;
  Reg r11;
  volatile uint32_t _12;
  Reg r12;

  // R13 is SP (stack pointer)
  volatile uint32_t _13;
  Reg r13;

  // R14 is LR (link register)
  volatile uint32_t _14;
  Reg r14;

  // R15 is PC (program counter)
  volatile uint32_t _15;
  Reg r15;


} __attribute__((packed));

// System registers affecting control and status of the machine.
struct alignas(8) SR final {

  uint8_t _2;
  uint8_t n;  //  Negative condition flag.
  uint8_t _3;
  uint8_t z;  //  Zero condition flag
  uint8_t _4;
  uint8_t c;  //  Carry condition flag
  uint8_t _5;
  uint8_t v;  //  Overflow condition flag

  uint8_t _6;
  uint8_t ixc;  // Inexact (cumulative).
  uint8_t _7;
  uint8_t ofc;  // Overflow (cumulative).
  uint8_t _8;
  uint8_t ufc;  // Underflow (cumulative).
  uint8_t _9;
  uint8_t idc;  // Input denormal (cumulative).
  uint8_t _10;
  uint8_t ioc;  // Invalid operation (cumulative).
  uint8_t _11;
  uint8_t q;  //  Sticky overflow bit.

  uint8_t _padding[4];
} __attribute__((packed));

struct alignas(16) State final : public ArchState {


  GPR gpr;  // 528 bytes.
  SR sr;
  uint64_t _0;


} __attribute__((packed));

using AArch32State = State;

#pragma clang diagnostic pop
