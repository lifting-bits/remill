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

#include <glog/logging.h>

#include <cstdint>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Instruction.h"

namespace remill {
namespace sparc {

union Format0a {
  uint32_t flat;
  struct {
    uint32_t imm22 : 22;
    uint32_t op2 : 3;
    uint32_t rd : 5;
    uint32_t op : 2;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(Format0a) == 4, " ");

union Format0b {
  uint32_t flat;
  struct {
    int32_t disp22 : 22;
    uint32_t op2 : 3;
    uint32_t cond : 4;
    uint32_t a : 1;
    uint32_t op : 2;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(Format0b) == 4, " ");

union Format0c {
  uint32_t flat;
  struct {
    int32_t disp19 : 19;
    uint32_t p : 1;
    uint32_t cc0 : 1;
    uint32_t cc1 : 1;
    uint32_t op2 : 3;
    uint32_t cond : 4;
    uint32_t a : 1;
    uint32_t op : 2;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(Format0c) == 4, " ");

union Format0d {
  uint32_t flat;
  struct {
    uint32_t d16lo : 14;
    uint32_t rs1 : 5;
    uint32_t p : 1;
    uint32_t d16hi : 2;
    uint32_t op2 : 3;
    uint32_t rcond : 3;
    uint32_t must_be_zero : 1;  // Bit 28.
    uint32_t a : 1;
    uint32_t op : 2;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(Format0d) == 4, " ");

union Format3 {
  uint32_t flat;
  struct {
    uint32_t ai0_ai1_b : 14;
    uint32_t rs1 : 5;
    uint32_t op3 : 6;
    uint32_t rd : 5;
    uint32_t op : 2;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(Format3) == 4, " ");

// SPARC Format 3a
//_________________________________________________________________
//| op| rd      | op3       | rs1     |i|      asi      | rs2     |
//^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
union Format3ai0 {
  uint32_t flat;
  struct {
    uint32_t rs2 : 5;
    uint32_t asi : 8;
    uint32_t i : 1;  // Must be 0.
    uint32_t rs1 : 5;
    uint32_t op3 : 6;
    uint32_t rd : 5;
    uint32_t op : 2;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(Format3ai0) == 4, " ");

// SPARC Format 3a
//_________________________________________________________________
//| op| rd      | op3       | rs1     |i|       simm13            |
//^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
union Format3ai1 {
  uint32_t flat;
  struct {
    int32_t simm13 : 13;
    uint32_t i : 1;  // Must be 1.
    uint32_t rs1 : 5;
    uint32_t op3 : 6;
    uint32_t rd : 5;
    uint32_t op : 2;
  } __attribute__((packed));
} __attribute__((packed));

// SPARC Format 3b
//_________________________________________________________________
//| op| rd      | op3       | rs1    |     opf     |      rs2        |
//^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
union Format3b {
  uint32_t flat;
  struct {
    uint32_t rs2 : 5;
    uint32_t opf : 9;
    uint32_t rs1 : 5;
    uint32_t op3 : 6;
    uint32_t rd : 5;
    uint32_t op : 2;  // 3
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(Format3b) == 4, " ");

union Format3c {
  uint32_t flat;
  struct {
    uint32_t rs2 : 5;
    uint32_t opf : 9;
    uint32_t rs1 : 5;
    uint32_t op3 : 6;
    uint32_t cc0 : 1;
    uint32_t cc1 : 1;
    uint32_t _1 : 3;
    uint32_t op : 2;  // 3
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(Format3b) == 4, " ");

union Format3di0 {
  uint32_t flat;
  struct {
    uint32_t rs2 : 5;
    uint32_t _1 : 5;
    uint32_t rcond : 3;
    uint32_t i : 1;
    uint32_t rs1 : 5;
    uint32_t op3 : 6;
    uint32_t rd : 5;
    uint32_t op : 2;  // 3
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(Format3di0) == 4, " ");

union Format3di1 {
  uint32_t flat;
  struct {
    uint32_t simm10 : 10;
    uint32_t rcond : 3;
    uint32_t i : 1;
    uint32_t rs1 : 5;
    uint32_t op3 : 6;
    uint32_t rd : 5;
    uint32_t op : 2;  // 3
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(Format3di1) == 4, " ");

union Format3ei0 {
  uint32_t flat;
  struct {
    uint32_t rs2 : 5;
    uint32_t _1 : 7;
    uint32_t x : 1;
    uint32_t i : 1;  // Must be 0.
    uint32_t rs1 : 5;
    uint32_t op3 : 6;
    uint32_t rd : 5;
    uint32_t op : 2;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(Format3ei0) == 4, " ");

union Format3ei1 {
  uint32_t flat;
  struct {
    uint32_t shcnt32 : 5;
    uint32_t _1 : 7;
    uint32_t x : 1;
    uint32_t i : 1;  // Must be 0.
    uint32_t rs1 : 5;
    uint32_t op3 : 6;
    uint32_t rd : 5;
    uint32_t op : 2;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(Format3ei1) == 4, " ");

union Format3ei2 {
  uint32_t flat;
  struct {
    uint32_t shcnt64 : 6;
    uint32_t _1 : 6;
    uint32_t x : 1;
    uint32_t i : 1;  // Must be 0.
    uint32_t rs1 : 5;
    uint32_t op3 : 6;
    uint32_t rd : 5;
    uint32_t op : 2;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(Format3ei2) == 4, " ");

union Format3f {
  uint32_t flat;
  struct {
    uint32_t mmask : 4;
    uint32_t cmask : 3;
    uint32_t _1 : 6;
    uint32_t i : 1;  // Must be 1.
    uint32_t bits : 5;
    uint32_t op3 : 6;
    uint32_t _2 : 5;
    uint32_t op : 2;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(Format3f) == 4, " ");

union Format4a {
  uint32_t flat;
  struct {
    uint32_t rs2 : 5;
    uint32_t unused : 6;
    uint32_t cc0 : 1;
    uint32_t cc1 : 1;
    uint32_t i : 1;  // 0.
    uint32_t rs1 : 5;
    uint32_t op3 : 6;
    uint32_t rd : 5;
    uint32_t op : 2;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(Format4a) == 4, " ");

union Format4b {
  uint32_t flat;
  struct {
    int32_t simm11 : 11;
    uint32_t cc0 : 1;
    uint32_t cc1 : 1;
    uint32_t i : 1;  // 0.
    uint32_t rs1 : 5;
    uint32_t op3 : 6;
    uint32_t rd : 5;
    uint32_t op : 2;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(Format4b) == 4, " ");

union Format4c {
  uint32_t flat;
  struct {
    uint32_t rs2 : 5;
    uint32_t unused : 6;
    uint32_t cc0 : 1;
    uint32_t cc1 : 1;
    uint32_t i : 1;  // 0.
    uint32_t cond : 4;
    uint32_t cc2 : 1;
    uint32_t op3 : 6;
    uint32_t rd : 5;
    uint32_t op : 2;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(Format4c) == 4, " ");

union Format4d {
  uint32_t flat;
  struct {
    int32_t simm11 : 11;
    uint32_t cc0 : 1;
    uint32_t cc1 : 1;
    uint32_t i : 1;  // 0.
    uint32_t cond : 4;
    uint32_t cc2 : 1;
    uint32_t op3 : 6;
    uint32_t rd : 5;
    uint32_t op : 2;
  } __attribute__((packed));
} __attribute__((packed));
static_assert(sizeof(Format4d) == 4, " ");

extern const std::string_view kCCRName[4];
extern const std::string_view kFCCRName[8];
extern const std::string_view kReadIntRegName[32];
extern const std::string_view kWriteIntRegName[32];
extern const std::string_view kCondName[16];
extern const std::string_view kFCondName[16];
extern const std::string_view kRCondName[8];

void AddSrcRegop(Instruction &inst, const char *reg_name, unsigned size);
void AddDestRegop(Instruction &inst, const char *reg_name, unsigned size);
void AddImmop(Instruction &inst, uint64_t imm, unsigned size, bool is_signed);

}  // namespace sparc

namespace sparc32 {

bool TryDecode(Instruction &inst);

}  // namespace sparc32
}  // namespace remill
