/*
 * Copyright (c) 2026-present Trail of Bits, Inc.
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

struct alignas(8) GPR final {

  // Prevents LLVM from casting the whole `GPR` into an `i64` to access `x0`.
  volatile uint64_t _0;
  Reg x0;
  volatile uint64_t _1;
  Reg x1;
  volatile uint64_t _2;
  Reg x2;
  volatile uint64_t _3;
  Reg x3;
  volatile uint64_t _4;
  Reg x4;
  volatile uint64_t _5;
  Reg x5;
  volatile uint64_t _6;
  Reg x6;
  volatile uint64_t _7;
  Reg x7;
  volatile uint64_t _8;
  Reg x8;
  volatile uint64_t _9;
  Reg x9;
  volatile uint64_t _10;
  Reg x10;
  volatile uint64_t _11;
  Reg x11;
  volatile uint64_t _12;
  Reg x12;
  volatile uint64_t _13;
  Reg x13;
  volatile uint64_t _14;
  Reg x14;
  volatile uint64_t _15;
  Reg x15;
  volatile uint64_t _16;
  Reg x16;
  volatile uint64_t _17;
  Reg x17;
  volatile uint64_t _18;
  Reg x18;
  volatile uint64_t _19;
  Reg x19;
  volatile uint64_t _20;
  Reg x20;
  volatile uint64_t _21;
  Reg x21;
  volatile uint64_t _22;
  Reg x22;
  volatile uint64_t _23;
  Reg x23;
  volatile uint64_t _24;
  Reg x24;
  volatile uint64_t _25;
  Reg x25;
  volatile uint64_t _26;
  Reg x26;
  volatile uint64_t _27;
  Reg x27;
  volatile uint64_t _28;
  Reg x28;
  volatile uint64_t _29;
  Reg x29;
  volatile uint64_t _30;
  Reg x30;
  volatile uint64_t _31;
  Reg x31;

} __attribute__((packed));

static_assert(512 == sizeof(GPR), "Invalid structure packing of `GPR`.");

struct alignas(8) FPR final {

  // Prevents LLVM from casting the whole `FPR` into an `i64` to access `f0`.
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

struct alignas(8) FCSR final {
  volatile uint32_t _0;
  uint32_t fcsr;

  volatile uint8_t _1;
  uint8_t frm;
  volatile uint8_t _2;
  uint8_t fflags;

  uint32_t _padding;
} __attribute__((packed));

static_assert(16 == sizeof(FCSR), "Invalid structure packing of `FCSR`.");

struct alignas(8) RISCVState : public ArchState {
  GPR gpr;
  FPR fpr;

  volatile uint64_t _pc;
  Reg pc;

  FCSR fcsr;

  // LR/SC reservation state used by the Ghidra Sleigh spec.
  volatile uint64_t _reserve_address;
  Reg reserve_address;

  volatile uint8_t _reserve;
  uint8_t reserve;

  volatile uint8_t _reserve_length;
  uint8_t reserve_length;

  uint8_t _padding[4];
} __attribute__((packed));

struct State : public RISCVState {};

#pragma clang diagnostic pop
