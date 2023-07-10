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

  // Prevents LLVM from casting a `GPR` into an `i64` to access `X0`.
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
  Reg sp;  // Stack pointer.

  volatile uint64_t _32;
  Reg pc;  // Program counter of the CURRENT instruction!

} __attribute__((packed));

static_assert(528 == sizeof(GPR), "Invalid structure packing of `GPR`.");

union PSTATE final {
  uint64_t flat;
  struct {

    // Bit 0.
    uint64_t N : 1;  // Negative condition flag.
    uint64_t Z : 1;  // Zero condition flag.
    uint64_t C : 1;  // Carry condition flag.
    uint64_t V : 1;  // Overflow condition flag.

    // Bit 4.
    uint64_t D : 1;  // Debug mask bit [AArch64 only].
    uint64_t A : 1;  // Asynchronous abort mask bit.
    uint64_t I : 1;  // IRQ mask bit.
    uint64_t F : 1;  // FIQ mask bit.

    // Bit 8.
    uint64_t SS : 1;  // Single-step bit.
    uint64_t IL : 1;  // Illegal state bit.
    uint64_t EL : 2;  // Exception Level (see above).

    // Bit 12.
    uint64_t nRW : 1;  // not Register Width: 0=64, 1=32
    uint64_t SP : 1;  // Stack pointer select: 0=SP0, 1=SPx [AArch64 only]
    uint64_t Q : 1;  // Cumulative saturation flag [AArch32 only]
    uint64_t GE : 4;  // Greater than or Equal flags [AArch32 only]

    // Bit 19.
    uint64_t IT : 8;  // If-then state [AArch32 only]
    uint64_t J : 1;  // Jazelle state [AArch32 only]
    uint64_t T : 1;  // Thumb state [AArch32 only]
    uint64_t E : 1;  // Endian state [AArch32 only]
    uint64_t M : 5;  // Mode field (see above) [AArch32 only]
    uint64_t _res0 : 29;  // bits 34-63.
  } __attribute__((packed));
} __attribute__((packed));

static_assert(8 == sizeof(PSTATE), "Invalid structure packing of `PSTATE`.");

// Condition code register. Really, this is a 32-bit register, but
// it is accessed 64-bit register instructions: `mrs <Xt>, nzcv`.
union NZCV {
  uint64_t flat;
  struct {
    uint64_t _0 : 28;
    uint64_t v : 1;  // Result overflowed, bit 28.
    uint64_t c : 1;  // Result produced a carry.
    uint64_t z : 1;  // Result is zero.
    uint64_t n : 1;  // Result is negative, bit 31.
    uint64_t _1 : 32;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(8 == sizeof(NZCV), "Invalid packing of `union NZCV`.");

#if COMPILING_WITH_GCC
using FPURoundingMode = uint64_t;
using FPUFlushToZeroMode = uint64_t;
using FPUDefaultNaNMode = uint64_t;
using FPUHalfPrecisionMode = uint64_t;
#else

enum FPURoundingMode : uint64_t {
  kFPURoundToNearestEven,  // RN (round nearest).
  kFPURoundUpInf,  // RP (round toward plus infinity).
  kFPURoundDownNegInf,  // RM (round toward minus infinity).
  kFPURoundToZero  // RZ (round toward zero).
};

enum FPUFlushToZeroMode : uint64_t {
  kFlushToZeroDisabled,
  kFlushToZeroEnabled
};

enum FPUDefaultNaNMode : uint64_t {
  kPropagateOriginalNaN,
  kPropagateDefaultNaN
};

enum FPUHalfPrecisionMode : uint64_t {
  kIEEEHalfPrecisionMode,
  kAlternativeHalfPrecisionMode
};
#endif

// Floating point control register. Really, this is a 32-bit register, but
// it is accessed 64-bit register instructions: `mrs <Xt>, fpcr`.
union FPCR {
  uint64_t flat;
  struct {
    uint64_t _res0 : 22;  // [21:0]
    FPURoundingMode rmode : 2;  // [23:22]
    FPUFlushToZeroMode fz : 1;  // [24]
    FPUDefaultNaNMode dn : 1;  // [25]
    FPUHalfPrecisionMode ahp : 1;  // [26]
    uint64_t _res1 : 5;  // [31:27]
    uint64_t _1 : 32;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(sizeof(FPCR) == 8, "Invalid packing of `union FPCR`.");

// Floating point status register. Really, this is a 32-bit register, but
// it is accessed 64-bit register instructions: `mrs <Xt>, fpsr`.
union FPSR {
  uint64_t flat;
  struct {
    uint64_t ioc : 1;  // Invalid operation cumulative exception bit.
    uint64_t dzc : 1;  // Division by zero cumulative exception bit.
    uint64_t ofc : 1;  // Overflow cumulative exception bit.
    uint64_t ufc : 1;  // Underflow cumulative exception bit.
    uint64_t ixc : 1;  // Inexact cumulative exception bit.
    uint64_t _res0 : 2;  // Bits 5 and 6.
    uint64_t idc : 1;  // Input denormal cumulative exception bit.
    uint64_t _res1 : 19;  // Bits 8 through 26.
    uint64_t qc : 1;  // Cumulative saturation bit, bit 27.
    uint64_t v : 1;  // Result overflowed, bit 28. [AArch32 only]
    uint64_t c : 1;  // Result produced a carry. [AArch32 only]
    uint64_t z : 1;  // Result is zero. [AArch32 only]
    uint64_t n : 1;  // Result is negative, bit 31. [AArch32 only]
    uint64_t _1 : 32;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(sizeof(FPSR) == 8, "Invalid packing of `union FPSR`.");

// System registers affecting control and status of the machine.
struct alignas(8) SR final {
  uint64_t _0;
  Reg tpidr_el0;  // Thread pointer for EL0.

  uint64_t _1;
  Reg tpidrro_el0;  // Read-only thread pointer for EL0.

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

  uint8_t _padding[6];
} __attribute__((packed));

static_assert(56 == sizeof(SR), "Invalid packing of `struct SR`.");

enum : size_t { kNumVecRegisters = 32 };

struct alignas(16) SIMD {
  vec128_t v[kNumVecRegisters];
};

static_assert(512 == sizeof(SIMD), "Invalid packing of `struct SIMD`.");

struct alignas(8) SleighFlagState {
  uint8_t NG;
  volatile uint8_t _1;
  uint8_t ZR;
  volatile uint8_t _2;
  uint8_t CY;
  volatile uint8_t _3;
  uint8_t OV;
  volatile uint8_t _4;
  uint8_t shift_carry;
  volatile uint8_t _5;
  uint8_t tmpCY;
  volatile uint8_t _6;
  uint8_t tmpOV;
  volatile uint8_t _7;
  uint8_t tmpNG;
  volatile uint8_t _8;
  uint8_t tmpZR;
  volatile uint8_t _9;
  uint8_t padding[6];
} __attribute__((packed));

static_assert(24 == sizeof(SleighFlagState),
              "Invalid packing of `struct SleighFlagState`.");

struct alignas(16) AArch64State : public ArchState {
  SIMD simd;  // 512 bytes.

  uint64_t _0;

  GPR gpr;  // 528 bytes.

  uint64_t _1;

  NZCV nzcv;  // 8 bytes (high 4 are unused).
  FPCR fpcr;  // 8 bytes (high 4 are unused).
  FPSR fpsr;  // 8 bytes (high 4 are unused).

  uint64_t _2;

  SR sr;  // 56 bytes.

  uint64_t _3;

  SleighFlagState sleigh_flags;

  uint8_t padding[8];

} __attribute__((packed));

static_assert((1152 + 16 + 24 + 8) == sizeof(AArch64State),
              "Invalid packing of `struct State`");

struct State : public AArch64State {};

#pragma clang diagnostic pop
