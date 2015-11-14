/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifdef PLAT_X86_REG_INFOS
# undef PLAT_X86_REG_INFOS
#endif

#ifdef REG_INFO
# undef REG_INFO
#endif

#ifdef REG_INFO64
# undef REG_INFO64
#endif

// REG_INFO(read_sel, write_sel, name)
#define PLAT_X86_REG_INFOS() \
    REG_INFO(gpr.rax.byte.high, gpr.rax.byte.high, AH) \
    REG_INFO(gpr.rbx.byte.high, gpr.rbx.byte.high, BH) \
    REG_INFO(gpr.rcx.byte.high, gpr.rcx.byte.high, CH) \
    REG_INFO(gpr.rdx.byte.high, gpr.rdx.byte.high, DH) \
    REG_INFO(gpr.rax.byte.low, gpr.rax.byte.low, AL) \
    REG_INFO(gpr.rbx.byte.low, gpr.rbx.byte.low, BL) \
    REG_INFO(gpr.rcx.byte.low, gpr.rcx.byte.low, CL) \
    REG_INFO(gpr.rdx.byte.low, gpr.rdx.byte.low, DL) \
    REG_INFO(gpr.rsi.byte.low, gpr.rsi.byte.low, SIL) \
    REG_INFO(gpr.rdi.byte.low, gpr.rdi.byte.low, DIL) \
    REG_INFO(gpr.rsp.byte.low, gpr.rsp.byte.low, SPL) \
    REG_INFO(gpr.rbp.byte.low, gpr.rbp.byte.low, BPL) \
    REG_INFO64(gpr.r8.byte.low, gpr.r8.byte.low, R8B) \
    REG_INFO64(gpr.r9.byte.low, gpr.r9.byte.low, R9B) \
    REG_INFO64(gpr.r10.byte.low, gpr.r10.byte.low, R10B) \
    REG_INFO64(gpr.r11.byte.low, gpr.r11.byte.low, R11B) \
    REG_INFO64(gpr.r12.byte.low, gpr.r12.byte.low, R12B) \
    REG_INFO64(gpr.r13.byte.low, gpr.r13.byte.low, R13B) \
    REG_INFO64(gpr.r14.byte.low, gpr.r14.byte.low, R14B) \
    REG_INFO64(gpr.r15.byte.low, gpr.r15.byte.low, R15B) \
    REG_INFO(gpr.rax.word, gpr.rax.word, AX) \
    REG_INFO(gpr.rbx.word, gpr.rbx.word, BX) \
    REG_INFO(gpr.rcx.word, gpr.rcx.word, CX) \
    REG_INFO(gpr.rdx.word, gpr.rdx.word, DX) \
    REG_INFO(gpr.rsi.word, gpr.rsi.word, SI) \
    REG_INFO(gpr.rdi.word, gpr.rdi.word, DI) \
    REG_INFO(gpr.rsp.word, gpr.rsp.word, SP) \
    REG_INFO(gpr.rbp.word, gpr.rbp.word, BP) \
    REG_INFO64(gpr.r8.word, gpr.r8.word, R8W) \
    REG_INFO64(gpr.r9.word, gpr.r9.word, R9W) \
    REG_INFO64(gpr.r10.word, gpr.r10.word, R10W) \
    REG_INFO64(gpr.r11.word, gpr.r11.word, R11W) \
    REG_INFO64(gpr.r12.word, gpr.r12.word, R12W) \
    REG_INFO64(gpr.r13.word, gpr.r13.word, R13W) \
    REG_INFO64(gpr.r14.word, gpr.r14.word, R14W) \
    REG_INFO64(gpr.r15.word, gpr.r15.word, R15W) \
    REG_INFO(gpr.rip.word, gpr.rip.word, IP) \
    REG_INFO(gpr.rax.dword, gpr.rax.full, EAX) \
    REG_INFO(gpr.rbx.dword, gpr.rbx.full, EBX) \
    REG_INFO(gpr.rcx.dword, gpr.rcx.full, ECX) \
    REG_INFO(gpr.rdx.dword, gpr.rdx.full, EDX) \
    REG_INFO(gpr.rsi.dword, gpr.rsi.full, ESI) \
    REG_INFO(gpr.rdi.dword, gpr.rdi.full, EDI) \
    REG_INFO(gpr.rsp.dword, gpr.rsp.full, ESP) \
    REG_INFO(gpr.rbp.dword, gpr.rbp.full, EBP) \
    REG_INFO64(gpr.r8.dword, gpr.r8.full, R8D) \
    REG_INFO64(gpr.r9.dword, gpr.r9.full, R9D) \
    REG_INFO64(gpr.r10.dword, gpr.r10.full, R10D) \
    REG_INFO64(gpr.r11.dword, gpr.r11.full, R11D) \
    REG_INFO64(gpr.r12.dword, gpr.r12.full, R12D) \
    REG_INFO64(gpr.r13.dword, gpr.r13.full, R13D) \
    REG_INFO64(gpr.r14.dword, gpr.r14.full, R14D) \
    REG_INFO64(gpr.r15.dword, gpr.r15.full, R15D) \
    REG_INFO(gpr.rip.dword, gpr.rip.full, EIP) \
    REG_INFO(gpr.rax.full, gpr.rax.full, RAX) \
    REG_INFO(gpr.rbx.full, gpr.rbx.full, RBX) \
    REG_INFO(gpr.rcx.full, gpr.rcx.full, RCX) \
    REG_INFO(gpr.rdx.full, gpr.rdx.full, RDX) \
    REG_INFO(gpr.rsi.full, gpr.rsi.full, RSI) \
    REG_INFO(gpr.rdi.full, gpr.rdi.full, RDI) \
    REG_INFO(gpr.rsp.full, gpr.rsp.full, RSP) \
    REG_INFO(gpr.rbp.full, gpr.rbp.full, RBP) \
    REG_INFO64(gpr.r8.full, gpr.r8.full, R8) \
    REG_INFO64(gpr.r9.full, gpr.r9.full, R9) \
    REG_INFO64(gpr.r10.full, gpr.r10.full, R10) \
    REG_INFO64(gpr.r11.full, gpr.r11.full, R11) \
    REG_INFO64(gpr.r12.full, gpr.r12.full, R12) \
    REG_INFO64(gpr.r13.full, gpr.r13.full, R13) \
    REG_INFO64(gpr.r14.full, gpr.r14.full, R14) \
    REG_INFO64(gpr.r15.full, gpr.r15.full, R15) \
    REG_INFO(gpr.rip.full, gpr.rip.full, RIP) \
    REG_INFO(seg.ss, seg.ss, SS) \
    REG_INFO(seg.es, seg.es, ES) \
    REG_INFO(seg.gs, seg.gs, GS) \
    REG_INFO(seg.fs, seg.fs, FS) \
    REG_INFO(seg.ds, seg.ds, DS) \
    REG_INFO(seg.cs, seg.cs, CS) \
    \
    REG_INFO(vec[0].xmm, vec[0].xmm, XMM0) \
    REG_INFO(vec[1].xmm, vec[1].xmm, XMM1) \
    REG_INFO(vec[2].xmm, vec[2].xmm, XMM2) \
    REG_INFO(vec[3].xmm, vec[3].xmm, XMM3) \
    REG_INFO(vec[4].xmm, vec[4].xmm, XMM4) \
    REG_INFO(vec[5].xmm, vec[5].xmm, XMM5) \
    REG_INFO(vec[6].xmm, vec[6].xmm, XMM6) \
    REG_INFO(vec[7].xmm, vec[7].xmm, XMM7) \
    REG_INFO(vec[8].xmm, vec[8].xmm, XMM8) \
    REG_INFO(vec[9].xmm, vec[9].xmm, XMM9) \
    REG_INFO(vec[10].xmm, vec[10].xmm, XMM10) \
    REG_INFO(vec[11].xmm, vec[11].xmm, XMM11) \
    REG_INFO(vec[12].xmm, vec[12].xmm, XMM12) \
    REG_INFO(vec[13].xmm, vec[13].xmm, XMM13) \
    REG_INFO(vec[14].xmm, vec[14].xmm, XMM14) \
    REG_INFO(vec[15].xmm, vec[15].xmm, XMM15) \
    \
    REG_INFO64(vec[16].xmm, vec[16].xmm, XMM16) \
    REG_INFO64(vec[17].xmm, vec[17].xmm, XMM17) \
    REG_INFO64(vec[18].xmm, vec[18].xmm, XMM18) \
    REG_INFO64(vec[19].xmm, vec[19].xmm, XMM19) \
    REG_INFO64(vec[20].xmm, vec[20].xmm, XMM20) \
    REG_INFO64(vec[21].xmm, vec[21].xmm, XMM21) \
    REG_INFO64(vec[22].xmm, vec[22].xmm, XMM22) \
    REG_INFO64(vec[23].xmm, vec[23].xmm, XMM23) \
    REG_INFO64(vec[24].xmm, vec[24].xmm, XMM24) \
    REG_INFO64(vec[25].xmm, vec[25].xmm, XMM25) \
    REG_INFO64(vec[26].xmm, vec[26].xmm, XMM26) \
    REG_INFO64(vec[27].xmm, vec[27].xmm, XMM27) \
    REG_INFO64(vec[28].xmm, vec[28].xmm, XMM28) \
    REG_INFO64(vec[29].xmm, vec[29].xmm, XMM29) \
    REG_INFO64(vec[30].xmm, vec[30].xmm, XMM30) \
    REG_INFO64(vec[31].xmm, vec[31].xmm, XMM31) \
    \
    REG_INFO64(vec[0].ymm, vec[0].ymm, YMM0) \
    REG_INFO64(vec[1].ymm, vec[1].ymm, YMM1) \
    REG_INFO64(vec[2].ymm, vec[2].ymm, YMM2) \
    REG_INFO64(vec[3].ymm, vec[3].ymm, YMM3) \
    REG_INFO64(vec[4].ymm, vec[4].ymm, YMM4) \
    REG_INFO64(vec[5].ymm, vec[5].ymm, YMM5) \
    REG_INFO64(vec[6].ymm, vec[6].ymm, YMM6) \
    REG_INFO64(vec[7].ymm, vec[7].ymm, YMM7) \
    REG_INFO64(vec[8].ymm, vec[8].ymm, YMM8) \
    REG_INFO64(vec[9].ymm, vec[9].ymm, YMM9) \
    REG_INFO64(vec[10].ymm, vec[10].ymm, YMM10) \
    REG_INFO64(vec[11].ymm, vec[11].ymm, YMM11) \
    REG_INFO64(vec[12].ymm, vec[12].ymm, YMM12) \
    REG_INFO64(vec[13].ymm, vec[13].ymm, YMM13) \
    REG_INFO64(vec[14].ymm, vec[14].ymm, YMM14) \
    REG_INFO64(vec[15].ymm, vec[15].ymm, YMM15) \
    REG_INFO64(vec[16].ymm, vec[16].ymm, YMM16) \
    REG_INFO64(vec[17].ymm, vec[17].ymm, YMM17) \
    REG_INFO64(vec[18].ymm, vec[18].ymm, YMM18) \
    REG_INFO64(vec[19].ymm, vec[19].ymm, YMM19) \
    REG_INFO64(vec[20].ymm, vec[20].ymm, YMM20) \
    REG_INFO64(vec[21].ymm, vec[21].ymm, YMM21) \
    REG_INFO64(vec[22].ymm, vec[22].ymm, YMM22) \
    REG_INFO64(vec[23].ymm, vec[23].ymm, YMM23) \
    REG_INFO64(vec[24].ymm, vec[24].ymm, YMM24) \
    REG_INFO64(vec[25].ymm, vec[25].ymm, YMM25) \
    REG_INFO64(vec[26].ymm, vec[26].ymm, YMM26) \
    REG_INFO64(vec[27].ymm, vec[27].ymm, YMM27) \
    REG_INFO64(vec[28].ymm, vec[28].ymm, YMM28) \
    REG_INFO64(vec[29].ymm, vec[29].ymm, YMM29) \
    REG_INFO64(vec[30].ymm, vec[30].ymm, YMM30) \
    REG_INFO64(vec[31].ymm, vec[31].ymm, YMM31) \
    \
    REG_INFO64(vec[0].zmm, vec[0].zmm, ZMM0) \
    REG_INFO64(vec[1].zmm, vec[1].zmm, ZMM1) \
    REG_INFO64(vec[2].zmm, vec[2].zmm, ZMM2) \
    REG_INFO64(vec[3].zmm, vec[3].zmm, ZMM3) \
    REG_INFO64(vec[4].zmm, vec[4].zmm, ZMM4) \
    REG_INFO64(vec[5].zmm, vec[5].zmm, ZMM5) \
    REG_INFO64(vec[6].zmm, vec[6].zmm, ZMM6) \
    REG_INFO64(vec[7].zmm, vec[7].zmm, ZMM7) \
    REG_INFO64(vec[8].zmm, vec[8].zmm, ZMM8) \
    REG_INFO64(vec[9].zmm, vec[9].zmm, ZMM9) \
    REG_INFO64(vec[10].zmm, vec[10].zmm, ZMM10) \
    REG_INFO64(vec[11].zmm, vec[11].zmm, ZMM11) \
    REG_INFO64(vec[12].zmm, vec[12].zmm, ZMM12) \
    REG_INFO64(vec[13].zmm, vec[13].zmm, ZMM13) \
    REG_INFO64(vec[14].zmm, vec[14].zmm, ZMM14) \
    REG_INFO64(vec[15].zmm, vec[15].zmm, ZMM15) \
    REG_INFO64(vec[16].zmm, vec[16].zmm, ZMM16) \
    REG_INFO64(vec[17].zmm, vec[17].zmm, ZMM17) \
    REG_INFO64(vec[18].zmm, vec[18].zmm, ZMM18) \
    REG_INFO64(vec[19].zmm, vec[19].zmm, ZMM19) \
    REG_INFO64(vec[20].zmm, vec[20].zmm, ZMM20) \
    REG_INFO64(vec[21].zmm, vec[21].zmm, ZMM21) \
    REG_INFO64(vec[22].zmm, vec[22].zmm, ZMM22) \
    REG_INFO64(vec[23].zmm, vec[23].zmm, ZMM23) \
    REG_INFO64(vec[24].zmm, vec[24].zmm, ZMM24) \
    REG_INFO64(vec[25].zmm, vec[25].zmm, ZMM25) \
    REG_INFO64(vec[26].zmm, vec[26].zmm, ZMM26) \
    REG_INFO64(vec[27].zmm, vec[27].zmm, ZMM27) \
    REG_INFO64(vec[28].zmm, vec[28].zmm, ZMM28) \
    REG_INFO64(vec[29].zmm, vec[29].zmm, ZMM29) \
    REG_INFO64(vec[30].zmm, vec[30].zmm, ZMM30) \
    REG_INFO64(vec[31].zmm, vec[31].zmm, ZMM31) \
    \
    REG_INFO(fpu.st[0].f, fpu.st[0].f, ST0) \
    REG_INFO(fpu.st[1].f, fpu.st[1].f, ST1) \
    REG_INFO(fpu.st[2].f, fpu.st[2].f, ST2) \
    REG_INFO(fpu.st[3].f, fpu.st[3].f, ST3) \
    REG_INFO(fpu.st[4].f, fpu.st[4].f, ST4) \
    REG_INFO(fpu.st[5].f, fpu.st[5].f, ST5) \
    REG_INFO(fpu.st[6].f, fpu.st[6].f, ST6) \
    REG_INFO(fpu.st[7].f, fpu.st[7].f, ST7) \
    \
    REG_INFO(fpu.ip, fpu.ip, FPU_LASTIP) \
    REG_INFO(fpu.cs, fpu.cs, FPU_LASTCS) \
    REG_INFO(fpu.dp, fpu.dp, FPU_LASTDP) \
    REG_INFO(fpu.ds, fpu.ds, FPU_LASTDS) \
    REG_INFO(fpu.fop, fpu.fop, FPU_OPCODE) \
    REG_INFO(fpu.cwd.flat, fpu.cwd.flat, FPU_CONTROL) \
    REG_INFO(fpu.swd.flat, fpu.swd.flat, FPU_STATUS) \
    REG_INFO(fpu.ftw, fpu.ftw, FPU_TAG)

