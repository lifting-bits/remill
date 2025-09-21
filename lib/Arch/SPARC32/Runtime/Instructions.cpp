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
#include <cmath>

#include "remill/Arch/Runtime/Float.h"
#include "remill/Arch/Runtime/Intrinsics.h"
#include "remill/Arch/Runtime/Operators.h"
#include "remill/Arch/SPARC32/Runtime/State.h"
#include "remill/Arch/SPARC32/Runtime/Types.h"

// A definition is required to ensure that LLVM doesn't optimize the `State` type out of the bytecode
// See https://github.com/lifting-bits/remill/pull/631#issuecomment-1279989004
State __remill_state;

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

#define REG_D0 state.fpreg.v[0].qwords.elems[0]

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

#define FSR_FCC0 state.fsr.fcc0
#define FSR_FCC1 state.fsr.fcc1
#define FSR_FCC2 state.fsr.fcc2
#define FSR_FCC3 state.fsr.fcc3

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

#define ASR_Y state.asr.yreg.dword
#define ASR_ASI state.asr.asi_flat
#define ASR_PC state.pc.aword
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

}  // namespace

// Takes the place of an unsupported instruction.
DEF_ISEL(UNSUPPORTED_INSTRUCTION) = HandleUnsupported;
DEF_ISEL(INVALID_INSTRUCTION) = HandleInvalidInstruction;

