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

#ifndef REMILL_ARCH_AARCH64_RUNTIME_STATE_H_
#define REMILL_ARCH_AARCH64_RUNTIME_STATE_H_

#pragma clang diagnostic push
#pragma clang diagnostic fatal "-Wpadded"

#define aword IF_64BIT_ELSE(qword, dword)

#include "remill/Arch/Runtime/State.h"
#include "remill/Arch/Runtime/Types.h"

struct Reg final {
  union {
    alignas(4) uint32_t dword;
    IF_64BIT(alignas(8) uint64_t qword;)
  } __attribute__((packed));

  IF_32BIT(uint32_t _padding0;)
} __attribute__((packed));

static_assert(sizeof(uint64_t) == sizeof(Reg), "Invalid packing of `Reg`.");
static_assert(0 == __builtin_offsetof(Reg, dword),
              "Invalid packing of `Reg::dword`.");

IF_64BIT(static_assert(0 == __builtin_offsetof(Reg, qword),
                       "Invalid packing of `Reg::qword`.");)

struct alignas(16) GPR final {
  // Prevents LLVM from casting a `GPR` into an `i64` to access `rax`.
  volatile uint64_t _0;
  Reg X0;
  volatile uint64_t _1;
  Reg X1;
  volatile uint64_t _2;
  Reg X2;
  volatile uint64_t _3;
  Reg X3;
  volatile uint64_t _4;
  Reg X4;
  volatile uint64_t _5;
  Reg X5;
  volatile uint64_t _6;
  Reg X6;
  volatile uint64_t _7;
  Reg X7;
  volatile uint64_t _8;
  Reg X8;
  volatile uint64_t _9;
  Reg X9;
  volatile uint64_t _10;
  Reg X10;
  volatile uint64_t _11;
  Reg X11;
  volatile uint64_t _12;
  Reg X12;
  volatile uint64_t _13;
  Reg X13;
  volatile uint64_t _14;
  Reg X14;
  volatile uint64_t _15;
  Reg X15;
  volatile uint64_t _16;
  Reg X16;
  volatile uint64_t _17;
  Reg X17;
  volatile uint64_t _18;
  Reg X18;
  volatile uint64_t _19;
  Reg X19;
  volatile uint64_t _20;
  Reg X20;
  volatile uint64_t _21;
  Reg X21;
  volatile uint64_t _22;
  Reg X22;
  volatile uint64_t _23;
  Reg X23;
  volatile uint64_t _24;
  Reg X24;
  volatile uint64_t _25;
  Reg X25;
  volatile uint64_t _26;
  Reg X26;
  volatile uint64_t _27;
  Reg X27;
  volatile uint64_t _28;
  Reg X28;
  volatile uint64_t _29;
  Reg X29;
  volatile uint64_t _30;
  Reg X30;

  // Reg 31 is called zero registers;
  volatile uint64_t _31;
  Reg X31;  // Stack pointer.

  // Program counter of the CURRENT instruction!
  volatile uint64_t _32;
  Reg PC;  // Program counter.

} __attribute__((packed));

static_assert(528 == sizeof(GPR), "Invalid structure packing of `GPR`.");

union alignas(8) NativeProcState final {
  uint64_t flat;
  struct {
    //  bit 0
    uint32_t N : 1;  //  Negative condition flag
    uint32_t Z : 1;  //  Zero condition flag
    uint32_t C : 1;  //  Carry condition flag
    uint32_t V : 1;  //  Overflow condition flag

    //  bit 4
    uint32_t D : 1;  //  Debug mask bit [AArch64 only]
    uint32_t A : 1;  //  Asynchronous abort mask bit
    uint32_t I : 1;  //  IRQ mask bit
    uint32_t F : 1;  //  FIQ mask bit

    //  bit 8
    uint32_t SS : 1;  //  Single-step bit
    uint32_t IL : 1;  //  Illegal state bit
    uint32_t EL : 2;  //  Exception Level (see above)

    //  bit 12
    uint32_t nRW : 1;  //  not Register Width: 0=64, 1=32
    uint32_t SP : 1;   //  Stack pointer select: 0=SP0, 1=SPx [AArch64 only]
    uint32_t Q : 1;    //  Cumulative saturation flag [AArch32 only]
    uint32_t GE : 4;   //  Greater than or Equal flags [AArch32 only]

    // bit 19
    uint32_t IT : 8;               // If-then state [AArch32 only]
    uint32_t J : 1;                // Jazelle state [AArch32 only]
    uint32_t T : 1;                // Thumb state [AArch32 only]
    uint32_t E : 1;                // Endian state [AArch32 only]
    uint32_t M : 5;                // Mode field (see above) [AArch32 only]
    uint32_t reserved_flags : 29;  // bits 34-63.
  } __attribute__((packed));
} __attribute__((packed));

static_assert(8 == sizeof(NativeProcState),
              "Invalid structure packing of `NativeProcState`.");

struct alignas(8) ProcState final {
  uint8_t _0;
  bool N;  //  Negative condition flag.
  uint8_t _1;
  bool Z;  //  Zero condition flag
  uint8_t _2;
  bool C;  //  Carry condition flag
  uint8_t _3;
  bool V;  //  Overflow condition flag
  uint8_t _4;
  uint8_t D;  //  Debug mask bit [AArch64 only]
  uint8_t _5;
  uint8_t A;  //  Asynchronous abort mask bit
  uint8_t _6;
  uint8_t I;  //  IRQ mask bit
  uint8_t _7;
  uint8_t F;  //  FIQ mask bit
  uint8_t _8;
  uint8_t SS;  //  Single-step bit
  uint8_t _9;
  uint8_t IL;  //  Illegal state bit
  uint8_t _10;
  uint8_t EL;  //  Exception Level (see above)
  uint8_t _11;
  uint8_t nRW;  //  not Register Width: 0=64, 1=32
  uint8_t _12;
  uint8_t SP;   //  Stack pointer select: 0=SP0, 1=SPx [AArch64 only]
  uint8_t _13;
  uint8_t Q;    //  Cumulative saturation flag [AArch32 only]
  uint8_t _14;
  uint8_t GE;   //  Greater than or Equal flags [AArch32 only]
  uint8_t _15;
  uint8_t IT;               // If-then state [AArch32 only]
  uint8_t _16;
  uint8_t J;                // Jazelle state [AArch32 only]
  uint8_t _17;
  uint8_t T;                // Thumb state [AArch32 only]
  uint8_t _18;
  uint8_t E;                // Endian state [AArch32 only]
  uint8_t _19;
  uint8_t M;                // Mode field (see above) [AArch32 only]
} __attribute__((packed));


static_assert(40 == sizeof(ProcState),
              "Invalid packing of `struct ProcState`");

struct alignas(16) State final : public ArchState {
  NativeProcState native_state;  // 8 bytes.
  ProcState pstate;  // 40 bytes.
  GPR gpr;  // 528 bytes.
} __attribute__((packed));

static_assert((576 + 16) == sizeof(State),
              "Invalid packing of `struct State`");

#pragma clang diagnostic pop

#endif  // REMILL_ARCH_AARCH64_RUNTIME_STATE_H_
