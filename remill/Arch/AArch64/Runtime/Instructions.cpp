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

#include "remill/Arch/Runtime/Intrinsics.h"
#include "remill/Arch/Runtime/Operators.h"

#include <fenv.h>
#include <algorithm>
#include <bitset>
#include <cmath>

#include "remill/Arch/AArch64/Runtime/State.h"
#include "remill/Arch/AArch64/Runtime/Operators.h"
#include "remill/Arch/AArch64/Runtime/Types.h"

#define REG_PC state.gpr.PC.qword
#define REG_SP state.gpr.SP.qword
#define REG_LP state.gpr.X30.qword
#define REG_FP state.gpr.X29.qword
#define REG_XZR state.gpr.X31.qword

#define REG_X0 state.gpr.X0.qword
#define REG_X1 state.gpr.X1.qword
#define REG_X2 state.gpr.X2.qword
#define REG_X3 state.gpr.X3.qword

#define REG_X4 state.gpr.X4.qword
#define REG_X5 state.gpr.X5.qword
#define REG_X6 state.gpr.X6.qword
#define REG_X7 state.gpr.X7.qword

#define REG_X8 state.gpr.X8.qword
#define REG_X9 state.gpr.X9.qword
#define REG_X10 state.gpr.X10.qword
#define REG_X11 state.gpr.X11.qword

#define REG_X12 state.gpr.X12.qword
#define REG_X13 state.gpr.X13.qword
#define REG_X14 state.gpr.X14.qword
#define REG_X15 state.gpr.X15.qword

#define REG_X16 state.gpr.X16.qword
#define REG_X17 state.gpr.X17.qword
#define REG_X18 state.gpr.X18.qword
#define REG_X19 state.gpr.X19.qword

#define REG_X20 state.gpr.X20.qword
#define REG_X21 state.gpr.X21.qword
#define REG_X22 state.gpr.X22.qword
#define REG_X23 state.gpr.X23.qword

#define REG_X24 state.gpr.X24.qword
#define REG_X25 state.gpr.X25.qword
#define REG_X26 state.gpr.X26.qword
#define REG_X27 state.gpr.X27.qword

#define REG_X28 state.gpr.X28.qword
#define REG_X29 state.gpr.X29.qword
#define REG_X30 state.gpr.X30.qword

#define FLAG_Z state.state.Z  // Zero flag.
#define FLAG_S state.state.S  // Sign flag.
#define FLAG_C state.state.C  // Carry flag.
#define FLAG_V state.state.V  // Overflow.
#define FLAG_N state.state.N  // Negative.

#define HYPER_CALL state.hyper_call
#define INTERRUPT_VECTOR state.interrupt_vector

namespace {
// Takes the place of an unsupported instruction.
DEF_SEM(HandleUnsupported) {
  return __remill_sync_hyper_call(
      memory, state, SyncHyperCall::kAArch64EmulateInstruction);
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

#include "remill/Arch/AArch64/Semantics/FLAGS.cpp"

#include "remill/Arch/AArch64/Semantics/BINARY.cpp"
#include "remill/Arch/AArch64/Semantics/BRANCH.cpp"
#include "remill/Arch/AArch64/Semantics/CALL_RET.cpp"
#include "remill/Arch/AArch64/Semantics/DATAXFER.cpp"
#include "remill/Arch/AArch64/Semantics/MISC.cpp"
