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
    alignas(8) uint64_t qword;
    alignas(4) uint32_t dword;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(sizeof(uint64_t) == sizeof(Reg), "Invalid packing of `Reg`.");
static_assert(0 == __builtin_offsetof(Reg, dword),
              "Invalid packing of `Reg::dword`.");

static_assert(0 == __builtin_offsetof(Reg, qword),
              "Invalid packing of `Reg::qword`.");

// General Purpose Registers
struct alignas(8) GPR final {
  volatile uint64_t _0;
  Reg zero;
  volatile uint64_t _1;
  Reg at;
  volatile uint64_t _2;
  Reg v0;
  volatile uint64_t _3;
  Reg v1;
  volatile uint64_t _4;
  Reg a0;
  volatile uint64_t _5;
  Reg a1;
  volatile uint64_t _6;
  Reg a2;
  volatile uint64_t _7;
  Reg a3;
  volatile uint64_t _8;
  Reg t0;
  volatile uint64_t _9;
  Reg t1;
  volatile uint64_t _10;
  Reg t2;
  volatile uint64_t _11;
  Reg t3;
  volatile uint64_t _12;
  Reg t4;
  volatile uint64_t _13;
  Reg t5;
  volatile uint64_t _14;
  Reg t6;
  volatile uint64_t _15;
  Reg t7;
  volatile uint64_t _16;
  Reg s0;
  volatile uint64_t _17;
  Reg s1;
  volatile uint64_t _18;
  Reg s2;
  volatile uint64_t _19;
  Reg s3;
  volatile uint64_t _20;
  Reg s4;
  volatile uint64_t _21;
  Reg s5;
  volatile uint64_t _22;
  Reg s6;
  volatile uint64_t _23;
  Reg s7;
  volatile uint64_t _24;
  Reg t8;
  volatile uint64_t _25;
  Reg t9;
  volatile uint64_t _26;
  Reg k0;
  volatile uint64_t _27;
  Reg k1;
  volatile uint64_t _28;
  Reg gp;
  volatile uint64_t _29;
  Reg sp;
  volatile uint64_t _30;
  Reg s8;
  volatile uint64_t _31;
  Reg ra;
  volatile uint64_t _32;
  Reg pc;

} __attribute__((packed));

static_assert(528 == sizeof(GPR), "Invalid structure packing of `GPR`.");

// Floating Pointer Registers
struct alignas(8) FPR final {
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

struct alignas(8) FlagRegisters final {
  volatile uint64_t _0;
  Reg ISAModeSwitch;
  // TODO: Move them elsewhere
  volatile uint64_t _1;
  Reg HI;
  volatile uint64_t _2;
  Reg LO;
} __attribute__((packed));

struct alignas(8) COP0Registers final {
  volatile uint64_t _0;
  Reg Index;
  volatile uint64_t _1;
  Reg Random;
  volatile uint64_t _2;
  Reg EntryLo0;
  volatile uint64_t _3;
  Reg EntryLo1;
  volatile uint64_t _4;
  Reg Context;
  volatile uint64_t _5;
  Reg PageMask;
  volatile uint64_t _6;
  Reg Wired;
  volatile uint64_t _7;
  Reg HWREna;
  volatile uint64_t _8;
  Reg BadVAddr;
  volatile uint64_t _9;
  Reg Count;
  volatile uint64_t _10;
  Reg EntryHi;
  volatile uint64_t _11;
  Reg Compare;
  volatile uint64_t _12;
  Reg Status;
  volatile uint64_t _13;
  Reg Cause;
  volatile uint64_t _14;
  Reg EPC;
  volatile uint64_t _15;
  Reg PRId;
  volatile uint64_t _16;
  Reg Config;
  volatile uint64_t _17;
  Reg LLAddr;
  volatile uint64_t _18;
  Reg WatchLo;
  volatile uint64_t _19;
  Reg WatchHi;
  volatile uint64_t _20;
  Reg XContext;
  volatile uint64_t _21;
  Reg cop0_reg21;
  volatile uint64_t _22;
  Reg cop0_reg22;
  volatile uint64_t _23;
  Reg Debug;
  volatile uint64_t _24;
  Reg DEPC;
  volatile uint64_t _25;
  Reg PerfCnt;
  volatile uint64_t _26;
  Reg ErrCtl;
  volatile uint64_t _27;
  Reg CacheErr;
  volatile uint64_t _28;
  Reg TagLo;
  volatile uint64_t _29;
  Reg TagHi;
  volatile uint64_t _30;
  Reg ErrorEPC;
  volatile uint64_t _31;
  Reg DESAVE;
} __attribute__((packed));

struct alignas(8) COP1Registers final {
  volatile uint64_t _0;
  Reg FCSR;
} __attribute__((packed));

struct alignas(8) MIPSState : public ArchState {
  GPR gpr;  // 528 bytes.

  uint64_t _0;

  FPR fpr;

  uint64_t _1;

  FlagRegisters flags;

  uint64_t _2;

  COP0Registers cop0;

  uint64_t _3;

  COP1Registers cop1;

  uint64_t _4;
} __attribute__((packed));

struct State : public MIPSState {};

#pragma clang diagnostic pop
