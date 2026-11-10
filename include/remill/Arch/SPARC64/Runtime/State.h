/*
 * Copyright (c) 2026 Trail of Bits, Inc.
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

// Machine state of the 64-bit SPARC architecture (`kArchSparc64`), which is
// lifted with Sleigh. It holds the registers of Ghidra's `SparcV9_64.sla`
// that the register table in `lib/Arch/Sleigh/SPARC64Arch.cpp` names; Sleigh
// registers without a field (the register window backing store, hypervisor
// state) become function-local values in lifted code.
//
// Every register is preceded by `volatile` padding, as in the other states,
// so that the optimizer never merges accesses to adjacent registers.

#pragma clang diagnostic push
#pragma clang diagnostic fatal "-Wpadded"

#include "remill/Arch/Runtime/State.h"
#include "remill/Arch/Runtime/Types.h"

struct SPARC64Reg final {
  volatile uint64_t _pad;
  uint64_t qword;
} __attribute__((packed));

static_assert(16 == sizeof(SPARC64Reg), "Invalid packing of `SPARC64Reg`.");

// Integer condition codes, floating-point condition codes and other one-byte
// registers.
struct SPARC64Flags final {
  volatile uint8_t _0;
  uint8_t x_nf;
  volatile uint8_t _1;
  uint8_t x_zf;
  volatile uint8_t _2;
  uint8_t x_vf;
  volatile uint8_t _3;
  uint8_t x_cf;
  volatile uint8_t _4;
  uint8_t i_nf;
  volatile uint8_t _5;
  uint8_t i_zf;
  volatile uint8_t _6;
  uint8_t i_vf;
  volatile uint8_t _7;
  uint8_t i_cf;
  volatile uint8_t _8;
  uint8_t fcc0;
  volatile uint8_t _9;
  uint8_t fcc1;
  volatile uint8_t _10;
  uint8_t fcc2;
  volatile uint8_t _11;
  uint8_t fcc3;
  volatile uint8_t _12;
  uint8_t asi;
  volatile uint8_t _13;
  uint8_t fprs;
  volatile uint8_t _14;
  uint8_t didrestore;  // Fake register of the Sleigh specification.
  volatile uint8_t _15;
  volatile uint8_t _16;
} __attribute__((packed));

static_assert(32 == sizeof(SPARC64Flags), "Invalid packing of `SPARC64Flags`.");

struct alignas(16) SPARC64State : public ArchState {

  // `fq0`-`fq60`; `fd0`-`fd62` and `fs0`-`fs31` overlay them.
  vec128_t fpreg[16];

  // `g0`-`g7`, `o0`-`o5`, `sp`, `o7`, `l0`-`l7`, `i0`-`i5`, `fp`, `i7`.
  SPARC64Reg gpr[32];

  SPARC64Reg pc;
  SPARC64Reg npc;
  SPARC64Reg fsr;

  // Ancillary state registers: `TICK`, `Y`, `CCR`, `PCR`, `PIC`, `GSR`,
  // `SOFTINT_SET`, `SOFTINT_CLR`, `SOFTINT`, `TICK_CMPR`, `STICK`,
  // `STICK_CMPR`.
  SPARC64Reg asr[12];

  // Privileged registers, in the order of Ghidra's register space from `TPC1`
  // to `GL` (see `SPARC64Arch::PopulateRegisterTable`).
  SPARC64Reg priv[30];

  SPARC64Flags flags;
};

static_assert(16 + 256 + 32 * 16 + 3 * 16 + 12 * 16 + 30 * 16 + 32 ==
                  sizeof(SPARC64State),
              "Invalid packing of `SPARC64State`.");

struct State : public SPARC64State {};

#pragma clang diagnostic pop
