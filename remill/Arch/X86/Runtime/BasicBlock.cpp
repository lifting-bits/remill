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

#include "remill/Arch/X86/Runtime/State.h"

extern "C" {

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-variable"

// Method that will implement a basic block. We will clone this method for
// each basic block in the code being lifted.
[[gnu::used]]
Memory *__remill_basic_block(Memory *memory, State &state, addr_t curr_pc) {

  bool branch_taken = false;
  addr_t zero = 0;

  // Note: These variables MUST be defined for all architectures.
  auto &STATE = state;
  auto &MEMORY = *memory;
  auto &PC = state.gpr.rip.aword;
  auto &BRANCH_TAKEN = branch_taken;

  // `PC` should already have the correct value, but it's nice to make sure
  // that `curr_pc` is used throughout, as it helps with certain downstream
  // uses to be able to depend on the optimizer not eliminating `curr_pc`.
  PC = curr_pc;

  // We will reference these variables from the bitcode side of things so that,
  // given a decoded register name and an operation type (read or write),
  // we can map the register to a specific field in the State structure.
  auto &AH = state.gpr.rax.byte.high;
  auto &BH = state.gpr.rbx.byte.high;
  auto &CH = state.gpr.rcx.byte.high;
  auto &DH = state.gpr.rdx.byte.high;
  auto &AL = state.gpr.rax.byte.low;
  auto &BL = state.gpr.rbx.byte.low;
  auto &CL = state.gpr.rcx.byte.low;
  auto &DL = state.gpr.rdx.byte.low;
#if 64 == ADDRESS_SIZE_BITS
  auto &SIL = state.gpr.rsi.byte.low;
  auto &DIL = state.gpr.rdi.byte.low;
  auto &SPL = state.gpr.rsp.byte.low;
  auto &BPL = state.gpr.rbp.byte.low;
  auto &R8B = state.gpr.r8.byte.low;
  auto &R9B = state.gpr.r9.byte.low;
  auto &R10B = state.gpr.r10.byte.low;
  auto &R11B = state.gpr.r11.byte.low;
  auto &R12B = state.gpr.r12.byte.low;
  auto &R13B = state.gpr.r13.byte.low;
  auto &R14B = state.gpr.r14.byte.low;
  auto &R15B = state.gpr.r15.byte.low;
#endif  // 64 == ADDRESS_SIZE_BITS
  auto &AX = state.gpr.rax.word;
  auto &BX = state.gpr.rbx.word;
  auto &CX = state.gpr.rcx.word;
  auto &DX = state.gpr.rdx.word;
  auto &SI = state.gpr.rsi.word;
  auto &DI = state.gpr.rdi.word;
  auto &SP = state.gpr.rsp.word;
  auto &BP = state.gpr.rbp.word;
#if 64 == ADDRESS_SIZE_BITS
  auto &R8W = state.gpr.r8.word;
  auto &R9W = state.gpr.r9.word;
  auto &R10W = state.gpr.r10.word;
  auto &R11W = state.gpr.r11.word;
  auto &R12W = state.gpr.r12.word;
  auto &R13W = state.gpr.r13.word;
  auto &R14W = state.gpr.r14.word;
  auto &R15W = state.gpr.r15.word;
#endif  // 64 == ADDRESS_SIZE_BITS
  auto &IP = state.gpr.rip.word;

  auto &EAX = state.gpr.rax.dword;
  auto &EBX = state.gpr.rbx.dword;
  auto &ECX = state.gpr.rcx.dword;
  auto &EDX = state.gpr.rdx.dword;
  auto &ESI = state.gpr.rsi.dword;
  auto &EDI = state.gpr.rdi.dword;
  auto &ESP = state.gpr.rsp.dword;
  auto &EBP = state.gpr.rbp.dword;
  auto &EIP = state.gpr.rip.dword;

#if 64 == ADDRESS_SIZE_BITS
  auto &R8D = state.gpr.r8.dword;
  auto &R9D = state.gpr.r9.dword;
  auto &R10D = state.gpr.r10.dword;
  auto &R11D = state.gpr.r11.dword;
  auto &R12D = state.gpr.r12.dword;
  auto &R13D = state.gpr.r13.dword;
  auto &R14D = state.gpr.r14.dword;
  auto &R15D = state.gpr.r15.dword;

  auto &RAX = state.gpr.rax.qword;
  auto &RBX = state.gpr.rbx.qword;
  auto &RCX = state.gpr.rcx.qword;
  auto &RDX = state.gpr.rdx.qword;
  auto &RSI = state.gpr.rsi.qword;
  auto &RDI = state.gpr.rdi.qword;
  auto &RSP = state.gpr.rsp.qword;
  auto &RBP = state.gpr.rbp.qword;
  auto &R8 = state.gpr.r8.qword;
  auto &R9 = state.gpr.r9.qword;
  auto &R10 = state.gpr.r10.qword;
  auto &R11 = state.gpr.r11.qword;
  auto &R12 = state.gpr.r12.qword;
  auto &R13 = state.gpr.r13.qword;
  auto &R14 = state.gpr.r14.qword;
  auto &R15 = state.gpr.r15.qword;
  auto &RIP = state.gpr.rip.qword;
#endif  // 64 == ADDRESS_SIZE_BITS

  auto &SS = state.seg.ss;
  auto &ES = state.seg.es;
  auto &GS = state.seg.gs;
  auto &FS = state.seg.fs;
  auto &DS = state.seg.ds;
  auto &CS = state.seg.cs;

  auto &SS_BASE = zero;
  auto &ES_BASE = zero;
  auto &GS_BASE = state.addr.gs_base.IF_64BIT_ELSE(qword, dword);
  auto &FS_BASE = state.addr.fs_base.IF_64BIT_ELSE(qword, dword);
  auto &DS_BASE = zero;
  auto &CS_BASE = zero;

#if HAS_FEATURE_AVX
#if HAS_FEATURE_AVX512
  auto &ZMM0 = state.vec[0].zmm;
  auto &ZMM1 = state.vec[1].zmm;
  auto &ZMM2 = state.vec[2].zmm;
  auto &ZMM3 = state.vec[3].zmm;
  auto &ZMM4 = state.vec[4].zmm;
  auto &ZMM5 = state.vec[5].zmm;
  auto &ZMM6 = state.vec[6].zmm;
  auto &ZMM7 = state.vec[7].zmm;
  auto &ZMM8 = state.vec[8].zmm;
  auto &ZMM9 = state.vec[9].zmm;
  auto &ZMM10 = state.vec[10].zmm;
  auto &ZMM11 = state.vec[11].zmm;
  auto &ZMM12 = state.vec[12].zmm;
  auto &ZMM13 = state.vec[13].zmm;
  auto &ZMM14 = state.vec[14].zmm;
  auto &ZMM15 = state.vec[15].zmm;
  auto &ZMM16 = state.vec[16].zmm;
  auto &ZMM17 = state.vec[17].zmm;
  auto &ZMM18 = state.vec[18].zmm;
  auto &ZMM19 = state.vec[19].zmm;
  auto &ZMM20 = state.vec[20].zmm;
  auto &ZMM21 = state.vec[21].zmm;
  auto &ZMM22 = state.vec[22].zmm;
  auto &ZMM23 = state.vec[23].zmm;
  auto &ZMM24 = state.vec[24].zmm;
  auto &ZMM25 = state.vec[25].zmm;
  auto &ZMM26 = state.vec[26].zmm;
  auto &ZMM27 = state.vec[27].zmm;
  auto &ZMM28 = state.vec[28].zmm;
  auto &ZMM29 = state.vec[29].zmm;
  auto &ZMM30 = state.vec[30].zmm;
  auto &ZMM31 = state.vec[31].zmm;
#endif  // HAS_FEATURE_AVX512

  auto &YMM0 = state.vec[0].ymm;
  auto &YMM1 = state.vec[1].ymm;
  auto &YMM2 = state.vec[2].ymm;
  auto &YMM3 = state.vec[3].ymm;
  auto &YMM4 = state.vec[4].ymm;
  auto &YMM5 = state.vec[5].ymm;
  auto &YMM6 = state.vec[6].ymm;
  auto &YMM7 = state.vec[7].ymm;
#if HAS_FEATURE_AVX || 64 == ADDRESS_SIZE_BITS
  auto &YMM8 = state.vec[8].ymm;
  auto &YMM9 = state.vec[9].ymm;
  auto &YMM10 = state.vec[10].ymm;
  auto &YMM11 = state.vec[11].ymm;
  auto &YMM12 = state.vec[12].ymm;
  auto &YMM13 = state.vec[13].ymm;
  auto &YMM14 = state.vec[14].ymm;
  auto &YMM15 = state.vec[15].ymm;
#endif  // HAS_FEATURE_AVX || 64 == ADDRESS_SIZE_BITS

#if HAS_FEATURE_AVX512
  auto &YMM16 = state.vec[16].ymm;
  auto &YMM17 = state.vec[17].ymm;
  auto &YMM18 = state.vec[18].ymm;
  auto &YMM19 = state.vec[19].ymm;
  auto &YMM20 = state.vec[20].ymm;
  auto &YMM21 = state.vec[21].ymm;
  auto &YMM22 = state.vec[22].ymm;
  auto &YMM23 = state.vec[23].ymm;
  auto &YMM24 = state.vec[24].ymm;
  auto &YMM25 = state.vec[25].ymm;
  auto &YMM26 = state.vec[26].ymm;
  auto &YMM27 = state.vec[27].ymm;
  auto &YMM28 = state.vec[28].ymm;
  auto &YMM29 = state.vec[29].ymm;
  auto &YMM30 = state.vec[30].ymm;
  auto &YMM31 = state.vec[31].ymm;
#endif  // HAS_FEATURE_AVX512
#endif  // HAS_FEATURE_AVX

  auto &XMM0 = state.vec[0].xmm;
  auto &XMM1 = state.vec[1].xmm;
  auto &XMM2 = state.vec[2].xmm;
  auto &XMM3 = state.vec[3].xmm;
  auto &XMM4 = state.vec[4].xmm;
  auto &XMM5 = state.vec[5].xmm;
  auto &XMM6 = state.vec[6].xmm;
  auto &XMM7 = state.vec[7].xmm;

#if HAS_FEATURE_AVX || 64 == ADDRESS_SIZE_BITS
  auto &XMM8 = state.vec[8].xmm;
  auto &XMM9 = state.vec[9].xmm;
  auto &XMM10 = state.vec[10].xmm;
  auto &XMM11 = state.vec[11].xmm;
  auto &XMM12 = state.vec[12].xmm;
  auto &XMM13 = state.vec[13].xmm;
  auto &XMM14 = state.vec[14].xmm;
  auto &XMM15 = state.vec[15].xmm;
#endif  // HAS_FEATURE_AVX || 64 == ADDRESS_SIZE_BITS

#if HAS_FEATURE_AVX512
  auto &XMM16 = state.vec[16].xmm;
  auto &XMM17 = state.vec[17].xmm;
  auto &XMM18 = state.vec[18].xmm;
  auto &XMM19 = state.vec[19].xmm;
  auto &XMM20 = state.vec[20].xmm;
  auto &XMM21 = state.vec[21].xmm;
  auto &XMM22 = state.vec[22].xmm;
  auto &XMM23 = state.vec[23].xmm;
  auto &XMM24 = state.vec[24].xmm;
  auto &XMM25 = state.vec[25].xmm;
  auto &XMM26 = state.vec[26].xmm;
  auto &XMM27 = state.vec[27].xmm;
  auto &XMM28 = state.vec[28].xmm;
  auto &XMM29 = state.vec[29].xmm;
  auto &XMM30 = state.vec[30].xmm;
  auto &XMM31 = state.vec[31].xmm;

#endif  // HAS_FEATURE_AVX512

  auto &ST0 = state.st.elems[0].val;
  auto &ST1 = state.st.elems[1].val;
  auto &ST2 = state.st.elems[2].val;
  auto &ST3 = state.st.elems[3].val;
  auto &ST4 = state.st.elems[4].val;
  auto &ST5 = state.st.elems[5].val;
  auto &ST6 = state.st.elems[6].val;
  auto &ST7 = state.st.elems[7].val;

#if 0  // TODO(pag): Don't emulate directly for now.
#if 32 == ADDRESS_SIZE_BITS
  auto &FPU_LASTIP = state.fpu.u.x86.ip;
  auto &FPU_LASTIP = state.fpu.u.x86.ip;
  auto &FPU_LASTCS = state.fpu.u.x86.cs;
  auto &FPU_LASTCS = state.fpu.u.x86.cs;
  auto &FPU_LASTDP = state.fpu.u.x86.dp;
  auto &FPU_LASTDP = state.fpu.u.x86.dp;
  auto &FPU_LASTDS = state.fpu.u.x86.ds;
  auto &FPU_LASTDS = state.fpu.u.x86.ds;
#else
  auto &FPU_LASTIP = state.fpu.u.amd64.ip;
  auto &FPU_LASTIP = state.fpu.u.amd64.ip;
  auto &FPU_LASTDP = state.fpu.u.amd64.dp;
  auto &FPU_LASTDP = state.fpu.u.amd64.dp;
#endif
#endif

  // MMX technology registers. For simplicity, these are implemented separately
  // from the FPU stack, and so they do not alias. This makes some things
  // easier and some things harder. Marshaling native/lifted state becomes
  // harder, but generating and optimizing bitcode becomes simpler. The trade-
  // off is that analysis and native states will diverge in strange ways
  // with code that mixes the two (X87 FPU ops, MMX ops).
  auto &MMX0 = state.mmx.elems[0].val.qwords.elems[0];
  auto &MMX1 = state.mmx.elems[1].val.qwords.elems[0];
  auto &MMX2 = state.mmx.elems[2].val.qwords.elems[0];
  auto &MMX3 = state.mmx.elems[3].val.qwords.elems[0];
  auto &MMX4 = state.mmx.elems[4].val.qwords.elems[0];
  auto &MMX5 = state.mmx.elems[5].val.qwords.elems[0];
  auto &MMX6 = state.mmx.elems[6].val.qwords.elems[0];
  auto &MMX7 = state.mmx.elems[7].val.qwords.elems[0];

  // Arithmetic flags. Data-flow analyses will clear these out ;-)
  auto &AF = state.aflag.af;
  auto &CF = state.aflag.cf;
  auto &DF = state.aflag.df;
  auto &OF = state.aflag.of;
  auto &PF = state.aflag.pf;
  auto &SF = state.aflag.sf;
  auto &ZF = state.aflag.zf;

  // Lifted code will be placed here in clones versions of this function.
  return memory;
}

#pragma clang diagnostic pop

}  // extern C

#include "remill/Arch/Runtime/Intrinsics.cpp"
