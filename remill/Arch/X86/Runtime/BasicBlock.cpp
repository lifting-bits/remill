/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include "remill/Arch/X86/Runtime/State.h"

extern "C" {

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-variable"

// Method that will implement a basic block. We will clone this method for
// each basic block in the code being lifted.
[[gnu::used]]
void __remill_basic_block(State &state, Memory &memory, addr_t curr_pc) {

  auto &STATE = state;
  auto &MEMORY = memory;
  auto &PC = state.gpr.rip.IF_64BIT_ELSE(qword, dword);

  // Define read- and write-specific aliases of each register. We will
  // reference these variables from the bitcode side of things so that,
  // given a decoded register name and an operation type (read or write),
  // we can map the register to a specific field in the State structure.
  auto &AH_read = state.gpr.rax.byte.high;
  auto &AH_write =  AH_read;
  auto &BH_read = state.gpr.rbx.byte.high;
  auto &BH_write =  BH_read;
  auto &CH_read = state.gpr.rcx.byte.high;
  auto &CH_write =  CH_read;
  auto &DH_read = state.gpr.rdx.byte.high;
  auto &DH_write =  DH_read;
  auto &AL_read = state.gpr.rax.byte.low;
  auto &AL_write =  AL_read;
  auto &BL_read = state.gpr.rbx.byte.low;
  auto &BL_write =  BL_read;
  auto &CL_read = state.gpr.rcx.byte.low;
  auto &CL_write =  CL_read;
  auto &DL_read = state.gpr.rdx.byte.low;
  auto &DL_write =  DL_read;
#if 64 == ADDRESS_SIZE_BITS
  auto &SIL_read = state.gpr.rsi.byte.low;
  auto &SIL_write =  SIL_read;
  auto &DIL_read = state.gpr.rdi.byte.low;
  auto &DIL_write =  DIL_read;
  auto &SPL_read = state.gpr.rsp.byte.low;
  auto &SPL_write =  SPL_read;
  auto &BPL_read = state.gpr.rbp.byte.low;
  auto &BPL_write =  BPL_read;
  auto &R8B_read = state.gpr.r8.byte.low;
  auto &R8B_write =  R8B_read;
  auto &R9B_read = state.gpr.r9.byte.low;
  auto &R9B_write =  R9B_read;
  auto &R10B_read = state.gpr.r10.byte.low;
  auto &R10B_write =  R10B_read;
  auto &R11B_read = state.gpr.r11.byte.low;
  auto &R11B_write =  R11B_read;
  auto &R12B_read = state.gpr.r12.byte.low;
  auto &R12B_write =  R12B_read;
  auto &R13B_read = state.gpr.r13.byte.low;
  auto &R13B_write =  R13B_read;
  auto &R14B_read = state.gpr.r14.byte.low;
  auto &R14B_write =  R14B_read;
  auto &R15B_read = state.gpr.r15.byte.low;
  auto &R15B_write =  R15B_read;
#endif  // 64 == ADDRESS_SIZE_BITS
  auto &AX_read = state.gpr.rax.word;
  auto &AX_write =  AX_read;
  auto &BX_read = state.gpr.rbx.word;
  auto &BX_write =  BX_read;
  auto &CX_read = state.gpr.rcx.word;
  auto &CX_write =  CX_read;
  auto &DX_read = state.gpr.rdx.word;
  auto &DX_write =  DX_read;
  auto &SI_read = state.gpr.rsi.word;
  auto &SI_write =  SI_read;
  auto &DI_read = state.gpr.rdi.word;
  auto &DI_write =  DI_read;
  auto &SP_read = state.gpr.rsp.word;
  auto &SP_write =  SP_read;
  auto &BP_read = state.gpr.rbp.word;
  auto &BP_write =  BP_read;
#if 64 == ADDRESS_SIZE_BITS
  auto &R8W_read = state.gpr.r8.word;
  auto &R8W_write =  R8W_read;
  auto &R9W_read = state.gpr.r9.word;
  auto &R9W_write =  R9W_read;
  auto &R10W_read = state.gpr.r10.word;
  auto &R10W_write =  R10W_read;
  auto &R11W_read = state.gpr.r11.word;
  auto &R11W_write =  R11W_read;
  auto &R12W_read = state.gpr.r12.word;
  auto &R12W_write =  R12W_read;
  auto &R13W_read = state.gpr.r13.word;
  auto &R13W_write =  R13W_read;
  auto &R14W_read = state.gpr.r14.word;
  auto &R14W_write =  R14W_read;
  auto &R15W_read = state.gpr.r15.word;
  auto &R15W_write =  R15W_read;
#endif  // 64 == ADDRESS_SIZE_BITS
  auto &IP_read = state.gpr.rip.word;
  auto &IP_write =  IP_read;
  auto &EAX_read = state.gpr.rax.dword;
  auto &EAX_write = state.gpr.rax.IF_64BIT_ELSE(qword, dword);
  auto &EBX_read = state.gpr.rbx.dword;
  auto &EBX_write = state.gpr.rbx.IF_64BIT_ELSE(qword, dword);
  auto &ECX_read = state.gpr.rcx.dword;
  auto &ECX_write = state.gpr.rcx.IF_64BIT_ELSE(qword, dword);
  auto &EDX_read = state.gpr.rdx.dword;
  auto &EDX_write = state.gpr.rdx.IF_64BIT_ELSE(qword, dword);
  auto &ESI_read = state.gpr.rsi.dword;
  auto &ESI_write = state.gpr.rsi.IF_64BIT_ELSE(qword, dword);
  auto &EDI_read = state.gpr.rdi.dword;
  auto &EDI_write = state.gpr.rdi.IF_64BIT_ELSE(qword, dword);
  auto &ESP_read = state.gpr.rsp.dword;
  auto &ESP_write = state.gpr.rsp.IF_64BIT_ELSE(qword, dword);
  auto &EBP_read = state.gpr.rbp.dword;
  auto &EBP_write = state.gpr.rbp.IF_64BIT_ELSE(qword, dword);
  auto &EIP_read = state.gpr.rip.dword;
  auto &EIP_write = state.gpr.rip.IF_64BIT_ELSE(qword, dword);

#if 64 == ADDRESS_SIZE_BITS
  auto &R8D_read = state.gpr.r8.dword;
  auto &R8D_write = state.gpr.r8.qword;
  auto &R9D_read = state.gpr.r9.dword;
  auto &R9D_write = state.gpr.r9.qword;
  auto &R10D_read = state.gpr.r10.dword;
  auto &R10D_write = state.gpr.r10.qword;
  auto &R11D_read = state.gpr.r11.dword;
  auto &R11D_write = state.gpr.r11.qword;
  auto &R12D_read = state.gpr.r12.dword;
  auto &R12D_write = state.gpr.r12.qword;
  auto &R13D_read = state.gpr.r13.dword;
  auto &R13D_write = state.gpr.r13.qword;
  auto &R14D_read = state.gpr.r14.dword;
  auto &R14D_write = state.gpr.r14.qword;
  auto &R15D_read = state.gpr.r15.dword;
  auto &R15D_write = state.gpr.r15.qword;

  auto &RAX_read = state.gpr.rax.qword;
  auto &RAX_write =  RAX_read;
  auto &RBX_read = state.gpr.rbx.qword;
  auto &RBX_write =  RBX_read;
  auto &RCX_read = state.gpr.rcx.qword;
  auto &RCX_write =  RCX_read;
  auto &RDX_read = state.gpr.rdx.qword;
  auto &RDX_write =  RDX_read;
  auto &RSI_read = state.gpr.rsi.qword;
  auto &RSI_write =  RSI_read;
  auto &RDI_read = state.gpr.rdi.qword;
  auto &RDI_write =  RDI_read;
  auto &RSP_read = state.gpr.rsp.qword;
  auto &RSP_write =  RSP_read;
  auto &RBP_read = state.gpr.rbp.qword;
  auto &RBP_write =  RBP_read;
  auto &R8_read = state.gpr.r8.qword;
  auto &R8_write =  R8_read;
  auto &R9_read = state.gpr.r9.qword;
  auto &R9_write =  R9_read;
  auto &R10_read = state.gpr.r10.qword;
  auto &R10_write =  R10_read;
  auto &R11_read = state.gpr.r11.qword;
  auto &R11_write =  R11_read;
  auto &R12_read = state.gpr.r12.qword;
  auto &R12_write =  R12_read;
  auto &R13_read = state.gpr.r13.qword;
  auto &R13_write =  R13_read;
  auto &R14_read = state.gpr.r14.qword;
  auto &R14_write =  R14_read;
  auto &R15_read = state.gpr.r15.qword;
  auto &R15_write =  R15_read;
  auto &RIP_read = state.gpr.rip.qword;
  auto &RIP_write =  RIP_read;
#endif  // 64 == ADDRESS_SIZE_BITS

  auto &SS_read = state.seg.ss;
  auto &SS_write =  SS_read;
  auto &ES_read = state.seg.es;
  auto &ES_write =  ES_read;
  auto &GS_read = state.seg.gs;
  auto &GS_write =  GS_read;
  auto &FS_read = state.seg.fs;
  auto &FS_write =  FS_read;
  auto &DS_read = state.seg.ds;
  auto &DS_write =  DS_read;
  auto &CS_read = state.seg.cs;
  auto &CS_write =  CS_read;

#if HAS_FEATURE_AVX
#if HAS_FEATURE_AVX512
  auto &ZMM0_read = state.vec[0].zmm;
  auto &ZMM0_write =  ZMM0_read;
  auto &ZMM1_read = state.vec[1].zmm;
  auto &ZMM1_write =  ZMM1_read;
  auto &ZMM2_read = state.vec[2].zmm;
  auto &ZMM2_write =  ZMM2_read;
  auto &ZMM3_read = state.vec[3].zmm;
  auto &ZMM3_write =  ZMM3_read;
  auto &ZMM4_read = state.vec[4].zmm;
  auto &ZMM4_write =  ZMM4_read;
  auto &ZMM5_read = state.vec[5].zmm;
  auto &ZMM5_write =  ZMM5_read;
  auto &ZMM6_read = state.vec[6].zmm;
  auto &ZMM6_write =  ZMM6_read;
  auto &ZMM7_read = state.vec[7].zmm;
  auto &ZMM7_write =  ZMM7_read;
  auto &ZMM8_read = state.vec[8].zmm;
  auto &ZMM8_write =  ZMM8_read;
  auto &ZMM9_read = state.vec[9].zmm;
  auto &ZMM9_write =  ZMM9_read;
  auto &ZMM10_read = state.vec[10].zmm;
  auto &ZMM10_write =  ZMM10_read;
  auto &ZMM11_read = state.vec[11].zmm;
  auto &ZMM11_write =  ZMM11_read;
  auto &ZMM12_read = state.vec[12].zmm;
  auto &ZMM12_write =  ZMM12_read;
  auto &ZMM13_read = state.vec[13].zmm;
  auto &ZMM13_write =  ZMM13_read;
  auto &ZMM14_read = state.vec[14].zmm;
  auto &ZMM14_write =  ZMM14_read;
  auto &ZMM15_read = state.vec[15].zmm;
  auto &ZMM15_write =  ZMM15_read;
  auto &ZMM16_read = state.vec[16].zmm;
  auto &ZMM16_write =  ZMM16_read;
  auto &ZMM17_read = state.vec[17].zmm;
  auto &ZMM17_write =  ZMM17_read;
  auto &ZMM18_read = state.vec[18].zmm;
  auto &ZMM18_write =  ZMM18_read;
  auto &ZMM19_read = state.vec[19].zmm;
  auto &ZMM19_write =  ZMM19_read;
  auto &ZMM20_read = state.vec[20].zmm;
  auto &ZMM20_write =  ZMM20_read;
  auto &ZMM21_read = state.vec[21].zmm;
  auto &ZMM21_write =  ZMM21_read;
  auto &ZMM22_read = state.vec[22].zmm;
  auto &ZMM22_write =  ZMM22_read;
  auto &ZMM23_read = state.vec[23].zmm;
  auto &ZMM23_write =  ZMM23_read;
  auto &ZMM24_read = state.vec[24].zmm;
  auto &ZMM24_write =  ZMM24_read;
  auto &ZMM25_read = state.vec[25].zmm;
  auto &ZMM25_write =  ZMM25_read;
  auto &ZMM26_read = state.vec[26].zmm;
  auto &ZMM26_write =  ZMM26_read;
  auto &ZMM27_read = state.vec[27].zmm;
  auto &ZMM27_write =  ZMM27_read;
  auto &ZMM28_read = state.vec[28].zmm;
  auto &ZMM28_write =  ZMM28_read;
  auto &ZMM29_read = state.vec[29].zmm;
  auto &ZMM29_write =  ZMM29_read;
  auto &ZMM30_read = state.vec[30].zmm;
  auto &ZMM30_write =  ZMM30_read;
  auto &ZMM31_read = state.vec[31].zmm;
  auto &ZMM31_write =  ZMM31_read;
#endif  // HAS_FEATURE_AVX512

  auto &YMM0_read = state.vec[0].ymm;
  auto &YMM0_write = AVX_SEL_XYZ(MM0_read);
  auto &YMM1_read = state.vec[1].ymm;
  auto &YMM1_write =  AVX_SEL_XYZ(MM1_read);
  auto &YMM2_read = state.vec[2].ymm;
  auto &YMM2_write =  AVX_SEL_XYZ(MM2_read);
  auto &YMM3_read = state.vec[3].ymm;
  auto &YMM3_write =  AVX_SEL_XYZ(MM3_read);
  auto &YMM4_read = state.vec[4].ymm;
  auto &YMM4_write =  AVX_SEL_XYZ(MM4_read);
  auto &YMM5_read = state.vec[5].ymm;
  auto &YMM5_write =  AVX_SEL_XYZ(MM5_read);
  auto &YMM6_read = state.vec[6].ymm;
  auto &YMM6_write =  AVX_SEL_XYZ(MM6_read);
  auto &YMM7_read = state.vec[7].ymm;
  auto &YMM7_write =  AVX_SEL_XYZ(MM7_read);
#if HAS_FEATURE_AVX || 64 == ADDRESS_SIZE_BITS
  auto &YMM8_read = state.vec[8].ymm;
  auto &YMM8_write =  AVX_SEL_XYZ(MM8_read);
  auto &YMM9_read = state.vec[9].ymm;
  auto &YMM9_write =  AVX_SEL_XYZ(MM9_read);
  auto &YMM10_read = state.vec[10].ymm;
  auto &YMM10_write =  AVX_SEL_XYZ(MM10_read);
  auto &YMM11_read = state.vec[11].ymm;
  auto &YMM11_write =  AVX_SEL_XYZ(MM11_read);
  auto &YMM12_read = state.vec[12].ymm;
  auto &YMM12_write = AVX_SEL_XYZ(MM12_read);
  auto &YMM13_read = state.vec[13].ymm;
  auto &YMM13_write = AVX_SEL_XYZ(MM13_read);
  auto &YMM14_read = state.vec[14].ymm;
  auto &YMM14_write = AVX_SEL_XYZ(MM14_read);
  auto &YMM15_read = state.vec[15].ymm;
  auto &YMM15_write = AVX_SEL_XYZ(MM15_read);
#endif  // HAS_FEATURE_AVX || 64 == ADDRESS_SIZE_BITS

#if HAS_FEATURE_AVX512
  auto &YMM16_read = state.vec[16].ymm;
  auto &YMM16_write = AVX_SEL_XYZ(MM16_read);
  auto &YMM17_read = state.vec[17].ymm;
  auto &YMM17_write = AVX_SEL_XYZ(MM17_read);
  auto &YMM18_read = state.vec[18].ymm;
  auto &YMM18_write = AVX_SEL_XYZ(MM18_read);
  auto &YMM19_read = state.vec[19].ymm;
  auto &YMM19_write = AVX_SEL_XYZ(MM19_read);
  auto &YMM20_read = state.vec[20].ymm;
  auto &YMM20_write = AVX_SEL_XYZ(MM20_read);
  auto &YMM21_read = state.vec[21].ymm;
  auto &YMM21_write = AVX_SEL_XYZ(MM21_read);
  auto &YMM22_read = state.vec[22].ymm;
  auto &YMM22_write = AVX_SEL_XYZ(MM22_read);
  auto &YMM23_read = state.vec[23].ymm;
  auto &YMM23_write = AVX_SEL_XYZ(MM23_read);
  auto &YMM24_read = state.vec[24].ymm;
  auto &YMM24_write = AVX_SEL_XYZ(MM24_read);
  auto &YMM25_read = state.vec[25].ymm;
  auto &YMM25_write = AVX_SEL_XYZ(MM25_read);
  auto &YMM26_read = state.vec[26].ymm;
  auto &YMM26_write = AVX_SEL_XYZ(MM26_read);
  auto &YMM27_read = state.vec[27].ymm;
  auto &YMM27_write = AVX_SEL_XYZ(MM27_read);
  auto &YMM28_read = state.vec[28].ymm;
  auto &YMM28_write = AVX_SEL_XYZ(MM28_read);
  auto &YMM29_read = state.vec[29].ymm;
  auto &YMM29_write = AVX_SEL_XYZ(MM29_read);
  auto &YMM30_read = state.vec[30].ymm;
  auto &YMM30_write = AVX_SEL_XYZ(MM30_read);
  auto &YMM31_read = state.vec[31].ymm;
  auto &YMM31_write = AVX_SEL_XYZ(MM31_read);
#endif  // HAS_FEATURE_AVX512
#endif  // HAS_FEATURE_AVX

  auto &XMM0_read = state.vec[0].xmm;
  auto &XMM0_write_legacy = XMM0_read;
  auto &XMM0_write = AVX_SEL_XYZ(MM0_read);
  auto &XMM1_read = state.vec[1].xmm;
  auto &XMM1_write_legacy = XMM1_read;
  auto &XMM1_write = AVX_SEL_XYZ(MM1_read);
  auto &XMM2_read = state.vec[2].xmm;
  auto &XMM2_write_legacy = XMM2_read;
  auto &XMM2_write = AVX_SEL_XYZ(MM2_read);
  auto &XMM3_read = state.vec[3].xmm;
  auto &XMM3_write_legacy = XMM3_read;
  auto &XMM3_write = AVX_SEL_XYZ(MM3_read);
  auto &XMM4_read = state.vec[4].xmm;
  auto &XMM4_write_legacy = XMM4_read;
  auto &XMM4_write = AVX_SEL_XYZ(MM4_read);
  auto &XMM5_read = state.vec[5].xmm;
  auto &XMM5_write_legacy = XMM5_read;
  auto &XMM5_write = AVX_SEL_XYZ(MM5_read);
  auto &XMM6_read = state.vec[6].xmm;
  auto &XMM6_write_legacy = XMM6_read;
  auto &XMM6_write = AVX_SEL_XYZ(MM6_read);
  auto &XMM7_read = state.vec[7].xmm;
  auto &XMM7_write_legacy = XMM7_read;
  auto &XMM7_write = AVX_SEL_XYZ(MM7_read);
#if HAS_FEATURE_AVX || 64 == ADDRESS_SIZE_BITS
  auto &XMM8_read = state.vec[8].xmm;
  auto &XMM8_write_legacy = XMM8_read;
  auto &XMM8_write = AVX_SEL_XYZ(MM8_read);
  auto &XMM9_read = state.vec[9].xmm;
  auto &XMM9_write_legacy = XMM9_read;
  auto &XMM9_write = AVX_SEL_XYZ(MM9_read);
  auto &XMM10_read = state.vec[10].xmm;
  auto &XMM10_write_legacy = XMM10_read;
  auto &XMM10_write = AVX_SEL_XYZ(MM10_read);
  auto &XMM11_read = state.vec[11].xmm;
  auto &XMM11_write_legacy = XMM11_read;
  auto &XMM11_write = AVX_SEL_XYZ(MM11_read);
  auto &XMM12_read = state.vec[12].xmm;
  auto &XMM12_write_legacy = XMM12_read;
  auto &XMM12_write = AVX_SEL_XYZ(MM12_read);
  auto &XMM13_read = state.vec[13].xmm;
  auto &XMM13_write_legacy = XMM13_read;
  auto &XMM13_write = AVX_SEL_XYZ(MM13_read);
  auto &XMM14_read = state.vec[14].xmm;
  auto &XMM14_write_legacy = XMM14_read;
  auto &XMM14_write = AVX_SEL_XYZ(MM14_read);
  auto &XMM15_read = state.vec[15].xmm;
  auto &XMM15_write_legacy = XMM15_read;
  auto &XMM15_write = AVX_SEL_XYZ(MM15_read);
#endif  // HAS_FEATURE_AVX || 64 == ADDRESS_SIZE_BITS

#if HAS_FEATURE_AVX512
  auto &XMM16_read = state.vec[16].xmm;
  auto &XMM16_write_legacy = XMM16_read;
  auto &XMM16_write = AVX_SEL_XYZ(MM16_read);
  auto &XMM17_read = state.vec[17].xmm;
  auto &XMM17_write_legacy = XMM17_read;
  auto &XMM17_write = AVX_SEL_XYZ(MM17_read);
  auto &XMM18_read = state.vec[18].xmm;
  auto &XMM18_write_legacy = XMM18_read;
  auto &XMM18_write = AVX_SEL_XYZ(MM18_read);
  auto &XMM19_read = state.vec[19].xmm;
  auto &XMM19_write_legacy = XMM19_read;
  auto &XMM19_write = AVX_SEL_XYZ(MM19_read);
  auto &XMM20_read = state.vec[20].xmm;
  auto &XMM20_write_legacy = XMM20_read;
  auto &XMM20_write = AVX_SEL_XYZ(MM20_read);
  auto &XMM21_read = state.vec[21].xmm;
  auto &XMM21_write_legacy = XMM21_read;
  auto &XMM21_write = AVX_SEL_XYZ(MM21_read);
  auto &XMM22_read = state.vec[22].xmm;
  auto &XMM22_write_legacy = XMM22_read;
  auto &XMM22_write = AVX_SEL_XYZ(MM22_read);
  auto &XMM23_read = state.vec[23].xmm;
  auto &XMM23_write_legacy = XMM23_read;
  auto &XMM23_write = AVX_SEL_XYZ(MM23_read);
  auto &XMM24_read = state.vec[24].xmm;
  auto &XMM24_write_legacy = XMM24_read;
  auto &XMM24_write = AVX_SEL_XYZ(MM24_read);
  auto &XMM25_read = state.vec[25].xmm;
  auto &XMM25_write_legacy = XMM25_read;
  auto &XMM25_write = AVX_SEL_XYZ(MM25_read);
  auto &XMM26_read = state.vec[26].xmm;
  auto &XMM26_write_legacy = XMM26_read;
  auto &XMM26_write = AVX_SEL_XYZ(MM26_read);
  auto &XMM27_read = state.vec[27].xmm;
  auto &XMM27_write_legacy = XMM27_read;
  auto &XMM27_write = AVX_SEL_XYZ(MM27_read);
  auto &XMM28_read = state.vec[28].xmm;
  auto &XMM28_write_legacy = XMM28_read;
  auto &XMM28_write = AVX_SEL_XYZ(MM28_read);
  auto &XMM29_read = state.vec[29].xmm;
  auto &XMM29_write_legacy = XMM29_read;
  auto &XMM29_write = AVX_SEL_XYZ(MM29_read);
  auto &XMM30_read = state.vec[30].xmm;
  auto &XMM30_write_legacy = XMM30_read;
  auto &XMM30_write = AVX_SEL_XYZ(MM30_read);
  auto &XMM31_read = state.vec[31].xmm;
  auto &XMM31_write_legacy = XMM31_read;
  auto &XMM31_write = AVX_SEL_XYZ(MM31_read);
#endif  // HAS_FEATURE_AVX512

  auto &ST0_read = state.st.element[0].val;
  auto &ST0_write =  ST0_read;
  auto &ST1_read = state.st.element[1].val;
  auto &ST1_write =  ST1_read;
  auto &ST2_read = state.st.element[2].val;
  auto &ST2_write =  ST2_read;
  auto &ST3_read = state.st.element[3].val;
  auto &ST3_write =  ST3_read;
  auto &ST4_read = state.st.element[4].val;
  auto &ST4_write =  ST4_read;
  auto &ST5_read = state.st.element[5].val;
  auto &ST5_write =  ST5_read;
  auto &ST6_read = state.st.element[6].val;
  auto &ST6_write =  ST6_read;
  auto &ST7_read = state.st.element[7].val;
  auto &ST7_write =  ST7_read;

#if 0  // TODO(pag): Don't emulate directly for now.
#if 32 == ADDRESS_SIZE_BITS
  auto &FPU_LASTIP_read = state.fpu.u.x86.ip;
  auto &FPU_LASTIP_write = state.fpu.u.x86.ip;
  auto &FPU_LASTCS_read = state.fpu.u.x86.cs;
  auto &FPU_LASTCS_write = state.fpu.u.x86.cs;
  auto &FPU_LASTDP_read = state.fpu.u.x86.dp;
  auto &FPU_LASTDP_write = state.fpu.u.x86.dp;
  auto &FPU_LASTDS_read = state.fpu.u.x86.ds;
  auto &FPU_LASTDS_write = state.fpu.u.x86.ds;
#else
  auto &FPU_LASTIP_read = state.fpu.u.amd64.ip;
  auto &FPU_LASTIP_write = state.fpu.u.amd64.ip;
  auto &FPU_LASTDP_read = state.fpu.u.amd64.dp;
  auto &FPU_LASTDP_write = state.fpu.u.amd64.dp;
#endif
#endif

  auto &FPU_OPCODE_read = state.fpu.fop;
  auto &FPU_OPCODE_write = state.fpu.fop;
  auto &FPU_CONTROL_read = state.fpu.cwd.flat;
  auto &FPU_CONTROL_write = state.fpu.cwd.flat;
  auto &FPU_STATUS_read = state.fpu.swd.flat;
  auto &FPU_STATUS_write = state.fpu.swd.flat;
  auto &FPU_TAG_read = state.fpu.ftw;
  auto &FPU_TAG_write = state.fpu.ftw;

  // MMX technology registers. For simplicity, these are implemented separately
  // from the FPU stack, and so they do not alias.
  //
  // TODO(pag): Have a "present" flag for each MMX register so that marshaling
  //            back to native code will know what to use.
  auto &MMX0_read = state.mmx.mmx[0].val;
  auto &MMX0_write = MMX0_read;
  auto &MMX1_read = state.mmx.mmx[1].val;
  auto &MMX1_write = MMX1_read;
  auto &MMX2_read = state.mmx.mmx[2].val;
  auto &MMX2_write = MMX2_read;
  auto &MMX3_read = state.mmx.mmx[3].val;
  auto &MMX3_write = MMX3_read;
  auto &MMX4_read = state.mmx.mmx[4].val;
  auto &MMX4_write = MMX4_read;
  auto &MMX5_read = state.mmx.mmx[5].val;
  auto &MMX5_write = MMX5_read;
  auto &MMX6_read = state.mmx.mmx[6].val;
  auto &MMX6_write = MMX6_read;
  auto &MMX7_read = state.mmx.mmx[7].val;
  auto &MMX7_write = MMX7_read;

  // Arithmetic flags. Data-flow analyses will clear these out ;-)
  auto &AF_write = state.aflag.af;
  auto &CF_write = state.aflag.cf;
  auto &DF_write = state.aflag.df;
  auto &OF_write = state.aflag.of;
  auto &PF_write = state.aflag.pf;
  auto &SF_write = state.aflag.sf;
  auto &ZF_write = state.aflag.zf;

  // Lifted code will be placed here in clones versions of this function.
}

#pragma clang diagnostic pop

}  // extern C

#include "remill/Arch/Runtime/Intrinsics.cpp"
