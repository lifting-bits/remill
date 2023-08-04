/*
 * Copyright (c) 2019 Trail of Bits, Inc.
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
  uint32_t dword;
} __attribute__((packed));


union PtrReg final {
  uint32_t dword;
} __attribute__((packed));

static_assert(sizeof(PtrReg) == 4);

struct GPR {

  // Prevents LLVM from casting a `GPR` into an `i64` to access `I0`.
  volatile uint32_t _0;
  Reg i0;
  volatile uint32_t _1;
  Reg i1;
  volatile uint32_t _2;
  Reg i2;
  volatile uint32_t _3;
  Reg i3;
  volatile uint32_t _4;
  Reg i4;
  volatile uint32_t _5;
  Reg i5;
  volatile uint32_t _6;
  PtrReg i6;
  volatile uint32_t _7;
  Reg i7;

  volatile uint32_t _8;
  Reg l0;
  volatile uint32_t _9;
  Reg l1;
  volatile uint32_t _10;
  Reg l2;
  volatile uint32_t _11;
  Reg l3;
  volatile uint32_t _12;
  Reg l4;
  volatile uint32_t _13;
  Reg l5;
  volatile uint32_t _14;
  Reg l6;
  volatile uint32_t _15;
  Reg l7;

  volatile uint32_t _16;
  Reg o0;
  volatile uint32_t _17;
  Reg o1;
  volatile uint32_t _18;
  Reg o2;
  volatile uint32_t _19;
  Reg o3;
  volatile uint32_t _20;
  Reg o4;
  volatile uint32_t _21;
  Reg o5;
  volatile uint32_t _22;
  PtrReg o6;
  volatile uint32_t _23;
  Reg o7;

  volatile uint32_t _24;
  Reg g0;
  volatile uint32_t _25;
  Reg g1;
  volatile uint32_t _26;
  Reg g2;
  volatile uint32_t _27;
  Reg g3;
  volatile uint32_t _28;
  Reg g4;
  volatile uint32_t _29;
  Reg g5;
  volatile uint32_t _30;
  Reg g6;
  volatile uint32_t _31;
  Reg g7;
};

enum AlternativeSpaceIdentifier : uint32_t {
  ASI_PST8_PRIMARY = 0xc0,
  ASI_PST8_SECONDARY,
  ASI_PST16_PRIMARY,
  ASI_PST16_SECONDARY,
  ASI_PST32_PRIMARY,
  ASI_PST32_SECONDARY,
  ASI_FL8_PRIMARY = 0xd0,
  ASI_FL8_SECONDARY,
  ASI_FL16_PRIMARY,
  ASI_FL16_SECONDARY,
  ASI_BLOCK_COMMIT_PRIMARY = 0xe0,
  ASI_TWINX_P = 0xe2,
  ASI_TWINX_S,
  ASI_BLOCK_PRIMARY = 0xf0,
  ASI_BLOCK_SECONDARY,
};

struct alignas(8) FPURegs final {
  vec128_t v[8];
} __attribute__((packed));

static_assert(128 == sizeof(struct FPURegs),
              "Invalid packing of `struct FPURegs`.");

struct FSRReg final {
  volatile uint8_t _0;
  uint8_t cexc;
  volatile uint8_t _1;
  uint8_t aexc;
  volatile uint8_t _2;
  uint8_t fcc0;
  volatile uint8_t _3;
  uint8_t reserve;
  volatile uint8_t _4;
  uint8_t ftt;
  volatile uint8_t _5;
  uint8_t ver;
  volatile uint8_t _6;
  uint8_t ns;
  volatile uint8_t _7;
  uint8_t tem;
  volatile uint8_t _8;
  uint8_t rd;
  volatile uint8_t _9;
  uint8_t fcc1;
  volatile uint8_t _10;
  uint8_t fcc2;
  volatile uint8_t _11;
  uint8_t fcc3;
} __attribute__((packed));

static_assert(24 == sizeof(struct FSRReg),
              "Invalid packing of `struct FSRReg`.");

// Condition Codes register flags
struct CCRFlags final {
  struct {
    volatile uint8_t _0;
    bool i_cf;
    volatile uint8_t _1;
    bool i_vf;
    volatile uint8_t _2;
    bool i_zf;
    volatile uint8_t _3;
    bool i_nf;
  } __attribute__((packed)) icc;
  struct {
    volatile uint8_t _0;
    bool x_cf;
    volatile uint8_t _1;
    bool x_vf;
    volatile uint8_t _2;
    bool x_zf;
    volatile uint8_t _3;
    bool x_nf;
  } __attribute__((packed)) xcc;
} __attribute__((packed));

union GSRFlags final {
  uint64_t flat;
  struct {
    uint64_t align : 3;
    uint64_t scale : 5;
    uint64_t reserved_0 : 17;
    uint64_t irnd : 2;
    uint64_t im : 1;
    uint64_t reserved_1 : 4;
    uint64_t mask : 32;
  } __attribute__((packed));
} __attribute__((packed));

struct ASR final {
  volatile uint32_t _0;
  Reg yreg;  // asr 0
  volatile uint32_t _1;
  Reg ccr;   // asr 2
  volatile uint32_t _2;
  Reg tick;  // asr 4
  volatile uint32_t _3;
  Reg pcr;   // asr16
  volatile uint32_t _4;
  Reg pic;   // asr 17
  volatile uint32_t _5;
  Reg gsr;   // asr 19
  volatile uint32_t _6;
  Reg softint_set; // asr 20
  volatile uint32_t _7;
  Reg softint_clr; // asr 21
  volatile uint32_t _8;
  Reg softint;     // asr 22
  volatile uint32_t _9;
  Reg tick_cmpr;   // asr 23
  volatile uint32_t _10;
  Reg stick;       // asr 24
  volatile uint32_t _11;
  Reg stick_cmpr;  // asr 25
  volatile uint32_t _12;
} __attribute__((packed));

struct CSR {
  uint8_t ccc;
  uint8_t padding0;
  uint16_t padding1;
  uint32_t padding2;
} __attribute__((packed));

static_assert(8 == sizeof(struct CSR), "Invalid packing of `struct CSR`.");

struct PSR {
  uint64_t tpc;
  uint64_t tnpc;
  uint64_t tstate;
  uint64_t tick;
  uint64_t tba;
  volatile uint8_t _0;  //padding
  uint8_t tt;
  uint8_t tl;
  union {
    uint16_t pstate;
    struct {
      uint16_t res1 : 1;
      uint16_t ie : 1;
      uint16_t priv : 1;
      uint16_t am : 1;
      uint16_t pef : 1;
      uint16_t res2 : 1;
      uint16_t mm : 1;
      uint16_t tle : 1;
      uint16_t cle : 1;
      uint16_t res3 : 1;
      uint16_t res4 : 1;
      uint16_t tct : 1;
      uint16_t padding : 4;
    } __attribute__((packed)) ps;
  } __attribute__((packed));
  volatile uint8_t _1;
  uint8_t pil;
  uint8_t cwp;
  uint8_t cansave;
  volatile uint8_t _2;
  uint8_t canrestore;
  uint8_t cleanwin;
  uint8_t otherwin;
  volatile uint8_t _3;
  union {
    uint8_t wstate;
    struct {
      uint8_t normal : 2;
      uint8_t other : 3;
      uint8_t padding : 3;
    } __attribute__((packed)) ws;
  } __attribute__((packed));
  uint8_t gl;
} __attribute__((packed));

struct alignas(16) SPARC32State : public ArchState {
  volatile uint64_t _0;
  FPURegs fpreg;  // 128 bytes
  volatile uint64_t _1;
  GPR gpr;  // 256 bytes
  volatile uint64_t _2;
  FSRReg fsr;  // 24 bytes
  volatile uint64_t _3;
  ASR asr;  // 168 bytes
  volatile uint32_t _4;
  CCRFlags ccr;
  volatile uint32_t _5;
  PSR psr;  // 56 bytes
  volatile uint32_t _6;
  Reg pc;  // 4 bytes
  volatile uint32_t _7;
  Reg next_pc;  // 4 bytes
  volatile uint32_t _8;
  Reg cwp;
  // fake register for sleigh
  uint8_t decompile_mode;
  volatile uint8_t _9;
  // fake register for sleigh
  uint8_t didrestore;
  volatile uint8_t _10;
  volatile uint8_t _padding[8];
};

struct State : public SPARC32State {};

#pragma clang diagnostic pop
