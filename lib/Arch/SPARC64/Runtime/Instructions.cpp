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

#include "remill/Arch/Runtime/Float.h"
#include "remill/Arch/Runtime/Intrinsics.h"
#include "remill/Arch/Runtime/Operators.h"
#include "remill/Arch/SPARC64/Runtime/State.h"
#include "remill/Arch/SPARC64/Runtime/Types.h"

// A definition is required to ensure that LLVM doesn't optimize the `State` type out of the bytecode
// See https://github.com/lifting-bits/remill/pull/631#issuecomment-1279989004
extern "C" {
extern State __remill_state = {};
}  // extern C

#define REG_PC state.pc.aword
#define REG_NPC state.next_pc.aword
#define REG_SP state.gpr.o6.aword
#define REG_FP state.gpr.i6.aword

#define REG_G0 state.gpr.g0.aword
#define REG_G1 state.gpr.g1.aword
#define REG_G7 state.gpr.g7.aword  // Thread local pointer

#define REG_L0 state.gpr.l0.aword
#define REG_L1 state.gpr.l1.aword
#define REG_L2 state.gpr.l2.aword
#define REG_L3 state.gpr.l3.aword
#define REG_L4 state.gpr.l4.aword
#define REG_L5 state.gpr.l5.aword
#define REG_L6 state.gpr.l6.aword
#define REG_L7 state.gpr.l7.aword

#define REG_I0 state.gpr.i0.aword
#define REG_I1 state.gpr.i1.aword
#define REG_I2 state.gpr.i2.aword
#define REG_I3 state.gpr.i3.aword
#define REG_I4 state.gpr.i4.aword
#define REG_I5 state.gpr.i5.aword
#define REG_I6 state.gpr.i6.aword
#define REG_I7 state.gpr.i7.aword

#define REG_O0 state.gpr.o0.aword
#define REG_O1 state.gpr.o1.aword
#define REG_O2 state.gpr.o2.aword
#define REG_O3 state.gpr.o3.aword
#define REG_O4 state.gpr.o4.aword
#define REG_O5 state.gpr.o5.aword
#define REG_O6 state.gpr.o6.aword
#define REG_O7 state.gpr.o7.aword

#define REG_F0 state.fpreg.v[0].floats.elems[0]
#define REG_F1 state.fpreg.v[0].floats.elems[1]
#define REG_F2 state.fpreg.v[0].floats.elems[2]
#define REG_F3 state.fpreg.v[0].floats.elems[3]

#define REG_D0 state.fpreg.v[0].doubles.elems[0]
#define REG_D2 state.fpreg.v[0].doubles.elems[1]

// GSR Register
#define GSR_ALIGN state.asr.gsr.align
#define GSR_MASK state.asr.gsr.mask

#define REG_Y state.asr.yreg.aword

#define FLAG_ICC_CF state.asr.ccr.icc.c
#define FLAG_ICC_VF state.asr.ccr.icc.v
#define FLAG_ICC_ZF state.asr.ccr.icc.z
#define FLAG_ICC_NF state.asr.ccr.icc.n

#define FLAG_XCC_CF state.asr.ccr.xcc.c
#define FLAG_XCC_VF state.asr.ccr.xcc.v
#define FLAG_XCC_ZF state.asr.ccr.xcc.z
#define FLAG_XCC_NF state.asr.ccr.xcc.n

#define REG_ICC state.asr.ccr.icc.flat
#define REG_XCC state.asr.ccr.xcc.flat
#define REG_CCC state.csr.ccc

#define FSR_FCC_0 state.fsr.fcc0
#define FSR_FCC_1 state.fsr.fcc1
#define FSR_FCC_2 state.fsr.fcc2
#define FSR_FCC_4 state.fsr.fcc4

#define FSR_CEXC state.fsr.cexc
#define FSR_FTT state.fsr.ftt
#define FSR_RD state.fsr.rd

#define PSR_TPC state.psr.tpc
#define PSR_TNPC state.psr.tnpc
#define PSR_TSTATE state.psr.tstate
#define PSR_TT state.psr.tt
#define PSR_TBA state.psr.tba
#define PSR_PSTATE state.psr.pstate
#define PSR_TL state.psr.tl
#define PSR_PIL state.psr.pil
#define PSR_WSTATE state.psr.wstate
#define PSR_CWP state.psr.cwp
#define PSR_CANSAVE state.psr.cansave
#define PSR_CANRESTORE state.psr.canrestore
#define PSR_CLEANWIN state.psr.cleanwin
#define PSR_OTHERWIN state.psr.otherwin
#define PSR_GL state.psr.gl

#define ASR_Y state.asr.yreg.aword
#define ASR_ASI state.asr.asi_flat
#define ASR_FPRS state.asr.fprs_flat
#define ASR_GSR state.asr.gsr.flat
#define ASR_SOFTINT state.asr.softint
#define ASR_STICK_CMPR state.asr.stick_cmpr
#define ASR_PAUSE state.asr.pause

#define HYPER_CALL state.hyper_call
#define INTERRUPT_VECTOR state.hyper_call_vector
#define HYPER_CALL_VECTOR state.hyper_call_vector

#if ADDRESS_SIZE_BITS == 64
#  define SPARC_STACKBIAS 0
#else
#  define SPARC_STACKBIAS 0
#endif

namespace {

// Takes the place of an unsupported instruction.
DEF_SEM(HandleUnsupported) {
  return __remill_sync_hyper_call(
      state, memory,
      SyncHyperCall::IF_32BIT_ELSE(kSPARC32EmulateInstruction,
                                   kSPARC64EmulateInstruction));
}

// Takes the place of an invalid instruction.
DEF_SEM(HandleInvalidInstruction) {
  HYPER_CALL = AsyncHyperCall::kInvalidInstruction;
  return memory;
}

DEF_HELPER(SAVE_WINDOW, RegisterWindow *window, RegisterWindow *&prev_window)
    ->void {

  // TODO(pag): These two lines should be uncommented for correctness, but then
  //            they don't result in as nice bitcode in McSema :-(
  //  window->prev_window = state.window;
  //  state.window = window;

  prev_window = window;

  window->l0 = Read(REG_L0);
  window->l1 = Read(REG_L1);
  window->l2 = Read(REG_L2);
  window->l3 = Read(REG_L3);
  window->l4 = Read(REG_L4);
  window->l5 = Read(REG_L5);
  window->l6 = Read(REG_L6);
  window->l7 = Read(REG_L7);

  window->i0 = Read(REG_I0);
  window->i1 = Read(REG_I1);
  window->i2 = Read(REG_I2);
  window->i3 = Read(REG_I3);
  window->i4 = Read(REG_I4);
  window->i5 = Read(REG_I5);
  window->i6 = Read(REG_I6);
  window->i7 = Read(REG_I7);

  // Move output register to input
  Write(REG_I0, REG_O0);
  Write(REG_I1, REG_O1);
  Write(REG_I2, REG_O2);
  Write(REG_I3, REG_O3);
  Write(REG_I4, REG_O4);
  Write(REG_I5, REG_O5);
  Write(REG_I6, REG_O6);
  Write(REG_I7, REG_O7);
}

DEF_HELPER(RESTORE_WINDOW, RegisterWindow *&prev_window)->void {

  const auto window = prev_window ? prev_window : state.window;
  if (!window) {
    memory = __remill_sync_hyper_call(state, memory,
                                      SyncHyperCall::kSPARCWindowUnderflow);
    return;
  }

  // TODO(pag): This next line should be uncommented for correctness, but then
  //            it means not as nice bitcode for mcsema.
  //  state.window = window->prev_window;

  // Move input register to output
  Write(REG_O0, REG_I0);
  Write(REG_O1, REG_I1);
  Write(REG_O2, REG_I2);
  Write(REG_O3, REG_I3);
  Write(REG_O4, REG_I4);
  Write(REG_O5, REG_I5);
  Write(REG_O6, REG_I6);
  Write(REG_O7, REG_I7);

  Write(REG_L0, window->l0);
  Write(REG_L1, window->l1);
  Write(REG_L2, window->l2);
  Write(REG_L3, window->l3);
  Write(REG_L4, window->l4);
  Write(REG_L5, window->l5);
  Write(REG_L6, window->l6);
  Write(REG_L7, window->l7);

  Write(REG_I0, window->i0);
  Write(REG_I1, window->i1);
  Write(REG_I2, window->i2);
  Write(REG_I3, window->i3);
  Write(REG_I4, window->i4);
  Write(REG_I5, window->i5);
  Write(REG_I6, window->i6);
  Write(REG_I7, window->i7);
}

}  // namespace

// Takes the place of an unsupported instruction.
DEF_ISEL(UNSUPPORTED_INSTRUCTION) = HandleUnsupported;
DEF_ISEL(INVALID_INSTRUCTION) = HandleInvalidInstruction;

#include "lib/Arch/SPARC32/Semantics/COND.cpp"
#include "lib/Arch/SPARC32/Semantics/FLAGS.cpp"
#include "lib/Arch/SPARC64/Semantics/ADDRESS.cpp"
#include "lib/Arch/SPARC64/Semantics/BINARY.cpp"
#include "lib/Arch/SPARC64/Semantics/BITBYTE.cpp"
#include "lib/Arch/SPARC64/Semantics/BRANCH.cpp"
#include "lib/Arch/SPARC64/Semantics/DATAXFER.cpp"
#include "lib/Arch/SPARC64/Semantics/FOP.cpp"
#include "lib/Arch/SPARC64/Semantics/LOGICAL.cpp"
#include "lib/Arch/SPARC64/Semantics/MISC.cpp"
#include "lib/Arch/SPARC64/Semantics/TRAP.cpp"
#include "lib/Arch/SPARC64/Semantics/VIS.cpp"
#include "lib/Arch/SPARC64/Semantics/WRASR.cpp"
