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

#include <algorithm>
#include <bitset>
#include <cmath>

// clang-format off
#include "remill/Arch/Name.h"
#include "remill/Arch/Runtime/Float.h"
#include "remill/Arch/Runtime/Intrinsics.h"
#include "remill/Arch/Runtime/Operators.h"
#include "remill/Arch/AArch32/Runtime/State.h"
#include "remill/Arch/AArch32/Runtime/Types.h"
#include "remill/Arch/AArch32/Runtime/Operators.h"

// clang-format on

// A definition is required to ensure that LLVM doesn't optimize the `State` type out of the bytecode
// See https://github.com/lifting-bits/remill/pull/631#issuecomment-1279989004
extern "C" {
extern State __remill_state = {};
}  // extern C

#define REG_PC state.gpr.r15.dword
#define REG_LR state.gpr.r14.dword
#define REG_SP state.gpr.r13.dword

#define HYPER_CALL state.hyper_call
#define INTERRUPT_VECTOR state.hyper_call_vector
#define HYPER_CALL_VECTOR state.hyper_call_vector

namespace {

// Takes the place of an unsupported instruction.
DEF_SEM(HandleUnsupported) {
  return __remill_sync_hyper_call(state, memory,
                                  SyncHyperCall::kAArch32EmulateInstruction);
}

// Takes the place of an invalid instruction.
DEF_SEM(HandleInvalidInstruction) {
  HYPER_CALL = AsyncHyperCall::kInvalidInstruction;
  return memory;
}

}  // namespace

// Takes the place of an unsupported instruction.
DEF_ISEL(UNSUPPORTED_INSTRUCTION) = HandleUnsupported;
DEF_ISEL(INVALID_INSTRUCTION) = HandleInvalidInstruction;

// clang-format on
