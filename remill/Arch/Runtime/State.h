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

#include "remill/Arch/Runtime/HyperCall.h"

struct ArchState {
 public:
  AsyncHyperCall::Name hyper_call;

  uint32_t _0;

  // Used to communicate the interrupt vector number to an intrinsic. The
  // issue is that the interrupt number is part of an instruction, and our
  // generic three-operand block/intrinsic form (state, mem, pc) doesn't
  // have room to hold a vector number.
  union {
    uint64_t addr_to_load;
    uint64_t addr_to_store;
    uint32_t hyper_call_vector;
  };
} __attribute__((packed));

static_assert(16 == sizeof(ArchState),
              "Invalid packing of `struct ArchState`.");
