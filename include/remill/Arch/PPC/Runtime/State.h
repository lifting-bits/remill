/*
 * Copyright (c) 2022-present Trail of Bits, Inc.
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

#if !defined(INCLUDED_FROM_REMILL)
#  include "remill/Arch/Runtime/Types.h"
#endif

struct Reg final {
  union {
    alignas(4) uint32_t dword;
    alignas(8) uint64_t qword;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(sizeof(uint64_t) == sizeof(Reg), "Invalid packing of `Reg`.");
static_assert(0 == __builtin_offsetof(Reg, dword),
              "Invalid packing of `Reg::dword`.");

static_assert(0 == __builtin_offsetof(Reg, qword),
              "Invalid packing of `Reg::qword`.");

// General Purpose Registers
struct alignas(8) GPR final {

  // Prevents LLVM from casting a `GPR` into an `i64` to access `r0`.
  volatile uint64_t _0;
  Reg r0;
  volatile uint64_t _1;
  Reg r1;
  volatile uint64_t _2;
  Reg r2;
  volatile uint64_t _3;
  Reg r3;
  volatile uint64_t _4;
  Reg r4;
  volatile uint64_t _5;
  Reg r5;
  volatile uint64_t _6;
  Reg r6;
  volatile uint64_t _7;
  Reg r7;
  volatile uint64_t _8;
  Reg r8;
  volatile uint64_t _9;
  Reg r9;
  volatile uint64_t _10;
  Reg r10;
  volatile uint64_t _11;
  Reg r11;
  volatile uint64_t _12;
  Reg r12;
  volatile uint64_t _13;
  Reg r13;
  volatile uint64_t _14;
  Reg r14;
  volatile uint64_t _15;
  Reg r15;
  volatile uint64_t _16;
  Reg r16;
  volatile uint64_t _17;
  Reg r17;
  volatile uint64_t _18;
  Reg r18;
  volatile uint64_t _19;
  Reg r19;
  volatile uint64_t _20;
  Reg r20;
  volatile uint64_t _21;
  Reg r21;
  volatile uint64_t _22;
  Reg r22;
  volatile uint64_t _23;
  Reg r23;
  volatile uint64_t _24;
  Reg r24;
  volatile uint64_t _25;
  Reg r25;
  volatile uint64_t _26;
  Reg r26;
  volatile uint64_t _27;
  Reg r27;
  volatile uint64_t _28;
  Reg r28;
  volatile uint64_t _29;
  Reg r29;
  volatile uint64_t _30;
  Reg r30;
  volatile uint64_t _31;
  Reg r31;

} __attribute__((packed));

static_assert(512 == sizeof(GPR), "Invalid structure packing of `GPR`.");

// Floating Pointer Registers
struct alignas(8) FPR final {

  // Prevents LLVM from casting an `FPR` into an `i64` to access `f0`.
  volatile uint64_t _0;
  Reg f0;
  volatile uint64_t _1;
  Reg f1;
  volatile uint64_t _2;
  Reg f2;
  volatile uint64_t _3;
  Reg f3;
  volatile uint64_t _4;
  Reg f4;
  volatile uint64_t _5;
  Reg f5;
  volatile uint64_t _6;
  Reg f6;
  volatile uint64_t _7;
  Reg f7;
  volatile uint64_t _8;
  Reg f8;
  volatile uint64_t _9;
  Reg f9;
  volatile uint64_t _10;
  Reg f10;
  volatile uint64_t _11;
  Reg f11;
  volatile uint64_t _12;
  Reg f12;
  volatile uint64_t _13;
  Reg f13;
  volatile uint64_t _14;
  Reg f14;
  volatile uint64_t _15;
  Reg f15;
  volatile uint64_t _16;
  Reg f16;
  volatile uint64_t _17;
  Reg f17;
  volatile uint64_t _18;
  Reg f18;
  volatile uint64_t _19;
  Reg f19;
  volatile uint64_t _20;
  Reg f20;
  volatile uint64_t _21;
  Reg f21;
  volatile uint64_t _22;
  Reg f22;
  volatile uint64_t _23;
  Reg f23;
  volatile uint64_t _24;
  Reg f24;
  volatile uint64_t _25;
  Reg f25;
  volatile uint64_t _26;
  Reg f26;
  volatile uint64_t _27;
  Reg f27;
  volatile uint64_t _28;
  Reg f28;
  volatile uint64_t _29;
  Reg f29;
  volatile uint64_t _30;
  Reg f30;
  volatile uint64_t _31;
  Reg f31;

} __attribute__((packed));

static_assert(512 == sizeof(FPR), "Invalid structure packing of `FPR`.");

// These are actually bitflags.
//
// Remill's notion of registers operates at a byte granularity so these need to
// take a full byte.
struct alignas(8) CRFlags final {

  volatile uint8_t _0;
  uint8_t cr0;
  volatile uint8_t _1;
  uint8_t cr1;
  volatile uint8_t _2;
  uint8_t cr2;
  volatile uint8_t _3;
  uint8_t cr3;
  volatile uint8_t _4;
  uint8_t cr4;
  volatile uint8_t _5;
  uint8_t cr5;
  volatile uint8_t _6;
  uint8_t cr6;
  volatile uint8_t _7;
  uint8_t cr7;

} __attribute__((packed));

struct alignas(8) XERFlags final {

  volatile uint8_t _0;
  uint8_t so;
  volatile uint8_t _1;
  uint8_t ov;
  volatile uint8_t _2;
  uint8_t ca;
  volatile uint8_t _3;
  uint8_t sl;
  // uint8_t _padding[2];

} __attribute__((packed));

// Instruction-Accessible Registers
struct alignas(8) IAR final {

  // Prevents LLVM from casting an `IAR` into an `i64` to access `cr`.
  volatile uint64_t _1;
  Reg cr;
  volatile uint64_t _2;
  Reg ctr;
  volatile uint64_t _3;
  Reg lr;
  volatile uint64_t _4;
  Reg xer;
  volatile uint64_t _5;
  Reg spefscr;
  volatile uint64_t _6;
  Reg acc;

} __attribute__((packed));

// Read-Only Performance Monitor Registers
struct alignas(8) UPM final {

  volatile uint64_t _0;
  Reg gc;

  // Counter registers
  volatile uint64_t _1;
  Reg c0;
  volatile uint64_t _2;
  Reg c1;
  volatile uint64_t _3;
  Reg c2;
  volatile uint64_t _4;
  Reg c3;

  // Local control registers
  volatile uint64_t _5;
  Reg lca0;
  volatile uint64_t _6;
  Reg lca1;
  volatile uint64_t _7;
  Reg lca2;
  volatile uint64_t _8;
  Reg lca3;
  volatile uint64_t _9;
  Reg lcb0;
  volatile uint64_t _10;
  Reg lcb1;
  volatile uint64_t _11;
  Reg lcb2;
  volatile uint64_t _12;
  Reg lcb3;

} __attribute__((packed));

// Time-Based Registers
struct alignas(8) TBR final {

  volatile uint64_t _0;
  Reg tbl;
  volatile uint64_t _1;
  Reg tbu;
  volatile uint64_t _2;
  Reg atbl;
  volatile uint64_t _3;
  Reg atbu;

} __attribute__((packed));

// General Special-Purpose Registers
struct alignas(8) SPRG final {

  volatile uint64_t _0;
  Reg r3;
  volatile uint64_t _1;
  Reg r4;
  volatile uint64_t _2;
  Reg r5;
  volatile uint64_t _3;
  Reg r6;
  volatile uint64_t _4;
  Reg r7;

} __attribute__((packed));

// L1 Cache Configuration
struct alignas(8) L1CFG final {

  volatile uint64_t _0;
  Reg r0;
  volatile uint64_t _1;
  Reg r1;

} __attribute__((packed));

// Signals
//
// These are signals that are commonly found on PPC devices
// They are implemented as registers here as Sleigh treats them that way
struct alignas(8) Signals final {
  volatile uint64_t _0;
  Reg tea;  // Transfer Error Acknowledge
  uint8_t _padding[8];
};

struct alignas(8) PPCState : public ArchState {

  GPR gpr;  // 528 bytes.

  uint64_t _0;

  FPR fpr;

  uint64_t _1;

  IAR iar;

  uint64_t _2;

  UPM upm;

  uint64_t _3;

  TBR tbr;

  uint64_t _4;

  Reg uspr;  // User Special-Purpose Register

  uint64_t _5;

  SPRG sprg;

  uint64_t _6;

  L1CFG l1cfg;

  uint64_t _7;

  Reg pc;  // This isn't exposed via PPC's API however Sleigh uses a "fake" register to maintain the program counter

  uint64_t _8;

  XERFlags xer_flags;

  uint64_t _9;

  CRFlags cr_flags;

  uint64_t _10;

  Signals signals;

} __attribute__((packed));

// static_assert((1152 + 16) == sizeof(PPCState),
//               "Invalid packing of `struct State`");

struct State : public PPCState {};

#pragma clang diagnostic pop
