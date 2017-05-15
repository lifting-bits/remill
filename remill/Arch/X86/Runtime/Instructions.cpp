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

#include "remill/Arch/X86/Runtime/State.h"
#include "remill/Arch/X86/Runtime/Types.h"
#include "remill/Arch/X86/Runtime/Operators.h"

#include <algorithm>
#include <bitset>
#include <fenv.h>
#include <cmath>

#define REG_IP state.gpr.rip.word
#define REG_EIP state.gpr.rip.dword
#define REG_RIP state.gpr.rip.qword

#define REG_SP state.gpr.rsp.word
#define REG_ESP state.gpr.rsp.dword
#define REG_RSP state.gpr.rsp.qword

#define REG_BP state.gpr.rbp.word
#define REG_EBP state.gpr.rbp.dword
#define REG_RBP state.gpr.rbp.qword

#define REG_AL state.gpr.rax.byte.low
#define REG_AH state.gpr.rax.byte.high
#define REG_AX state.gpr.rax.word
#define REG_EAX state.gpr.rax.dword
#define REG_RAX state.gpr.rax.qword

#define REG_BL state.gpr.rbx.byte.low
#define REG_BH state.gpr.rbx.byte.high
#define REG_BX state.gpr.rbx.word
#define REG_EBX state.gpr.rbx.dword
#define REG_RBX state.gpr.rbx.qword

#define REG_DL state.gpr.rdx.bytes.low
#define REG_DH state.gpr.rdx.bytes.high
#define REG_DX state.gpr.rdx.word
#define REG_EDX state.gpr.rdx.dword
#define REG_RDX state.gpr.rdx.qword

#define REG_CL state.gpr.rcx.byte.low
#define REG_CH state.gpr.rcx.byte.high
#define REG_CX state.gpr.rcx.word
#define REG_ECX state.gpr.rcx.dword
#define REG_RCX state.gpr.rcx.qword

#define REG_SIL state.gpr.rsi.bytes.low
#define REG_SI state.gpr.rsi.word
#define REG_ESI state.gpr.rsi.dword
#define REG_RSI state.gpr.rsi.qword

#define REG_DIL state.gpr.rdi.bytes.low
#define REG_DI state.gpr.rdi.word
#define REG_EDI state.gpr.rdi.dword
#define REG_RDI state.gpr.rdi.qword

#if 64 == ADDRESS_SIZE_BITS
# define REG_PC REG_RIP
# define REG_XIP REG_RIP
# define REG_XAX REG_RAX
# define REG_XDX REG_RDX
# define REG_XCX REG_RCX
# define REG_XSI REG_RSI
# define REG_XDI REG_RDI
# define REG_XSP REG_RSP
# define REG_XBP REG_RBP
# define REG_XBX REG_RBX
#else
# define REG_PC REG_EIP
# define REG_XIP REG_EIP
# define REG_XAX REG_EAX
# define REG_XDX REG_EDX
# define REG_XCX REG_ECX
# define REG_XSI REG_ESI
# define REG_XDI REG_EDI
# define REG_XSP REG_ESP
# define REG_XBP REG_EBP
# define REG_XBX REG_EBX
#endif  // 64 == ADDRESS_SIZE_BITS

#define FLAG_CF state.aflag.cf
#define FLAG_PF state.aflag.pf
#define FLAG_AF state.aflag.af
#define FLAG_ZF state.aflag.zf
#define FLAG_SF state.aflag.sf
#define FLAG_OF state.aflag.of
#define FLAG_DF state.aflag.df

#define X87_ST0 state.st.elems[0].val
#define X87_ST1 state.st.elems[1].val
#define X87_ST2 state.st.elems[2].val
#define X87_ST3 state.st.elems[3].val
#define X87_ST4 state.st.elems[4].val
#define X87_ST5 state.st.elems[5].val
#define X87_ST6 state.st.elems[6].val
#define X87_ST7 state.st.elems[7].val

#define REG_SS state.seg.ss
#define REG_ES state.seg.es
#define REG_DS state.seg.ds
#define REG_FS state.seg.fs
#define REG_GS state.seg.gs
#define REG_CS state.seg.cs

#define REG_SS_BASE 0
#define REG_ES_BASE 0
#define REG_DS_BASE 0
#define REG_FS_BASE state.addr.fs_base
#define REG_GS_BASE state.addr.gs_base
#define REG_CS_BASE 0

#define HYPER_CALL state.hyper_call
#define INTERRUPT_VECTOR state.interrupt_vector

namespace {
// Takes the place of an unsupported instruction.
DEF_SEM(HandleUnsupported) {
  return __remill_sync_hyper_call(
      memory, state, IF_64BIT_ELSE(SyncHyperCall::kAMD64EmulateInstruction,
                                   SyncHyperCall::kX86EmulateInstruction));
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

#include "remill/Arch/X86/Semantics/FLAGS.cpp"
#include "remill/Arch/X86/Semantics/BINARY.cpp"
#include "remill/Arch/X86/Semantics/BITBYTE.cpp"
#include "remill/Arch/X86/Semantics/CALL_RET.cpp"
#include "remill/Arch/X86/Semantics/CMOV.cpp"
#include "remill/Arch/X86/Semantics/COND_BR.cpp"
#include "remill/Arch/X86/Semantics/CONVERT.cpp"
#include "remill/Arch/X86/Semantics/DATAXFER.cpp"
#include "remill/Arch/X86/Semantics/INTERRUPT.cpp"
#include "remill/Arch/X86/Semantics/FLAGOP.cpp"
#include "remill/Arch/X86/Semantics/FMA.cpp"
#include "remill/Arch/X86/Semantics/LOGICAL.cpp"
#include "remill/Arch/X86/Semantics/MISC.cpp"
#include "remill/Arch/X86/Semantics/MMX.cpp"
#include "remill/Arch/X86/Semantics/NOP.cpp"
#include "remill/Arch/X86/Semantics/POP.cpp"
#include "remill/Arch/X86/Semantics/PREFETCH.cpp"
#include "remill/Arch/X86/Semantics/PUSH.cpp"
#include "remill/Arch/X86/Semantics/ROTATE.cpp"
#include "remill/Arch/X86/Semantics/RTM.cpp"
#include "remill/Arch/X86/Semantics/SEMAPHORE.cpp"
#include "remill/Arch/X86/Semantics/SHIFT.cpp"
#include "remill/Arch/X86/Semantics/SSE.cpp"
#include "remill/Arch/X86/Semantics/STRINGOP.cpp"
#include "remill/Arch/X86/Semantics/SYSCALL.cpp"
#include "remill/Arch/X86/Semantics/SYSTEM.cpp"
#include "remill/Arch/X86/Semantics/UNCOND_BR.cpp"
#include "remill/Arch/X86/Semantics/XOP.cpp"
#include "remill/Arch/X86/Semantics/X87.cpp"
