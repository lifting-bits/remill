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
  addr_t qword;
} __attribute__((packed));

static_assert(sizeof(Reg) == 8, "Invalid size of `Reg`.");

union PtrReg final {
  addr_t qword;
} __attribute__((packed));

static_assert(sizeof(PtrReg) == 8, "Invalid size of `PtrReg`.");

struct GPR {

  // Prevents LLVM from casting a `GPR` into an `i64` to access `I0`.
  volatile addr_t _0;
  Reg i0;
  volatile addr_t _1;
  Reg i1;
  volatile addr_t _2;
  Reg i2;
  volatile addr_t _3;
  Reg i3;
  volatile addr_t _4;
  Reg i4;
  volatile addr_t _5;
  Reg i5;
  volatile addr_t _6;
  Reg i6;
  volatile addr_t _7;
  Reg i7;

  volatile addr_t _8;
  Reg l0;
  volatile addr_t _9;
  Reg l1;
  volatile addr_t _10;
  Reg l2;
  volatile addr_t _11;
  Reg l3;
  volatile addr_t _12;
  Reg l4;
  volatile addr_t _13;
  Reg l5;
  volatile addr_t _14;
  Reg l6;
  volatile addr_t _15;
  Reg l7;

  volatile addr_t _16;
  Reg o0;
  volatile addr_t _17;
  Reg o1;
  volatile addr_t _18;
  Reg o2;
  volatile addr_t _19;
  Reg o3;
  volatile addr_t _20;
  Reg o4;
  volatile addr_t _21;
  Reg o5;
  volatile addr_t _22;
  Reg o6;
  volatile addr_t _23;
  Reg o7;

  volatile addr_t _24;
  Reg g0;
  volatile addr_t _25;
  Reg g1;
  volatile addr_t _26;
  Reg g2;
  volatile addr_t _27;
  Reg g3;
  volatile addr_t _28;
  Reg g4;
  volatile addr_t _29;
  Reg g5;
  volatile addr_t _30;
  Reg g6;
  volatile addr_t _31;
  Reg g7;
};

static_assert(512 == sizeof(GPR), "Invalid packing of `struct GPR`.");

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

struct FPURegs final {
  vec128_t v[16];
} __attribute__((packed));

static_assert(((128 * 16) / 8) == sizeof(struct FPURegs),
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

// Integer condition code register flags
struct ICCRFlags final {
  struct {
    volatile uint8_t _0;
    bool c;
    volatile uint8_t _1;
    bool v;
    volatile uint8_t _2;
    bool z;
    volatile uint8_t _3;
    bool n;
  } __attribute__((packed)) icc, xcc;
} __attribute__((packed));

static_assert(16 == sizeof(struct ICCRFlags),
              "Invalid packing of `struct ICCRFlags`.");

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
  Reg yreg;  // ASR 0
  volatile uint64_t _0;
  ICCRFlags ccr;  // ASR 2
  volatile uint64_t _1;
  union {
    uint64_t asi_flat;
    struct {
      uint64_t asi : 8;  // ASR 3
      uint64_t padding_1 : 56;
    } __attribute__((packed));
  } __attribute__((packed));
  volatile uint64_t _2;
  uint64_t tick;  // ASR 4
  volatile uint64_t _3;
  union {
    uint64_t fprs_flat;
    struct {
      uint64_t fprs : 3;  // ASR 6
      uint64_t padding_2 : 61;
    } __attribute__((packed));
  } __attribute__((packed));
  volatile uint64_t _4;
  GSRFlags gsr;
  volatile uint64_t _5;
  uint64_t softint;  // ASR 20
  volatile uint64_t _6;
  uint64_t stick;  // ASR 24
  volatile uint64_t _7;
  uint64_t stick_cmpr;  // ASR 25
  volatile uint64_t _8;
  uint64_t cfr;  // ASR 26
  volatile uint64_t _9;
  uint64_t pause;  // ASR 27
  volatile uint64_t _10;
  uint64_t mwait;  // ASR 28
};

static_assert(192 == sizeof(struct ASR), "Invalid packing of `struct ASR`.");

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

struct RegisterWindow {
  volatile addr_t _0;
  addr_t l0;
  volatile addr_t _1;
  addr_t l1;
  volatile addr_t _2;
  addr_t l2;
  volatile addr_t _3;
  addr_t l3;
  volatile addr_t _4;
  addr_t l4;
  volatile addr_t _5;
  addr_t l5;
  volatile addr_t _6;
  addr_t l6;
  volatile addr_t _7;
  addr_t l7;

  volatile addr_t _8;
  addr_t i0;
  volatile addr_t _9;
  addr_t i1;
  volatile addr_t _10;
  addr_t i2;
  volatile addr_t _11;
  addr_t i3;
  volatile addr_t _12;
  addr_t i4;
  volatile addr_t _13;
  addr_t i5;
  volatile addr_t _14;
  addr_t i6;
  volatile addr_t _15;
  addr_t i7;

  volatile addr_t _16;
  RegisterWindow *prev_window;
};

struct alignas(16) State : public ArchState {
  FPURegs fpreg;  // 512 bytes
  volatile uint64_t _0;
  GPR gpr;  // 512 bytes
  volatile uint64_t _1;
  ASR asr;  // 176 bytes
  volatile uint64_t _2;
  PSR psr;  // 56 bytes
  volatile uint64_t _3;
  FSRReg fsr;  // 24 bytes
  volatile uint64_t _4;
  CSR csr;  // 8 bytes
  volatile uint64_t _5;
  Reg pc;  // 8 bytes
  volatile uint64_t _6;
  Reg next_pc;  // 8 bytes
  volatile uint64_t _7;

  // NOTE(pag): This *must* go at the end, as if we change the target arch/data
  //            layout, then we want to make sure that the offset of this
  //            remains the same and doesn't shift other things around.
#if defined(INCLUDED_FROM_REMILL)
  uint64_t window;
#else
  RegisterWindow *window;  // smuggled.
  static_assert(sizeof(RegisterWindow *) == 8,
                "Invalid size of `RegisterWindow`");
#endif
};

using SPARCState = State;

#pragma clang diagnostic pop
