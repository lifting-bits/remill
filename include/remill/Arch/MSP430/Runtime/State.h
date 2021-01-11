/*
 * Copyright (c) 2021 Trail of Bits, Inc.
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
  addr_t word;
} __attribute__((packed));

struct NZCV {
  bool n;
  bool _0;
  bool c;
  bool _1;
  bool z;
  bool _2;
  bool v;
  bool _3;
};

union StatusReg {
  addr_t word;
  struct {
    uint16_t gc:1;  // Carry flag.
    uint16_t z:1;  // Zero flag.
    uint16_t n:1;  // Negative number flag.
    uint16_t gie:1;  // Global interrupt enable.
    uint16_t cpuoff:1;  // CPU off.
    uint16_t oscoff:1;  // Oscillator off.
    uint16_t scg0:1;  // System clock generator.
    uint16_t scg1:1;  // System clock generator.
    uint16_t v:1;  // Overflow flag.
    uint16_t _reserved:7;
  };
} __attribute__((packed));

static_assert(sizeof(StatusReg) == 2);

struct GPR {
  Reg r0;  // Program counter.
  uint16_t _0;
  Reg r1;  // Stack pointer.
  uint16_t _1;
  StatusReg r2;  // Status register.
  uint16_t _2;

  // NOTE(pag): `r3` is the constant zero.

  Reg r4;
  uint16_t _4;
  Reg r5;
  uint16_t _5;
  Reg r6;
  uint16_t _6;
  Reg r7;
  uint16_t _7;
  Reg r8;
  uint16_t _8;
  Reg r9;
  uint16_t _9;
  Reg r10;
  uint16_t _10;
  Reg r11;
  uint16_t _11;
  Reg r12;
  uint16_t _12;
  Reg r13;
  uint16_t _13;
  Reg r14;
  uint16_t _14;
  Reg r15;
  uint16_t _15;
} __attribute__((packed));

struct alignas(16) State : public ArchState {
  GPR gpr;
  NZCV nzcv;
  uint32_t padding[3];
};

using MSP430State = State;

#pragma clang diagnostic pop
