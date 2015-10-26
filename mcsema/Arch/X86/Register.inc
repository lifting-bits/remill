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
	REG_INFO(fpu.xmm[0], fpu.xmm[0], XMM0) \
	REG_INFO(fpu.xmm[1], fpu.xmm[1], XMM1) \
	REG_INFO(fpu.xmm[2], fpu.xmm[2], XMM2) \
	REG_INFO(fpu.xmm[3], fpu.xmm[3], XMM3) \
	REG_INFO(fpu.xmm[4], fpu.xmm[4], XMM4) \
	REG_INFO(fpu.xmm[5], fpu.xmm[5], XMM5) \
	REG_INFO(fpu.xmm[6], fpu.xmm[6], XMM6) \
	REG_INFO(fpu.xmm[7], fpu.xmm[7], XMM7) \
	REG_INFO(fpu.xmm[8], fpu.xmm[8], XMM8) \
	REG_INFO(fpu.xmm[9], fpu.xmm[9], XMM9) \
	REG_INFO(fpu.xmm[10], fpu.xmm[10], XMM10) \
	REG_INFO(fpu.xmm[11], fpu.xmm[11], XMM11) \
	REG_INFO(fpu.xmm[12], fpu.xmm[12], XMM12) \
	REG_INFO(fpu.xmm[13], fpu.xmm[13], XMM13) \
	REG_INFO(fpu.xmm[14], fpu.xmm[14], XMM14) \
	REG_INFO(fpu.xmm[15], fpu.xmm[15], XMM15) \
	REG_INFO(fpu.st[0].f, fpu.st[0].f, ST0) \
	REG_INFO(fpu.st[1].f, fpu.st[1].f, ST1) \
	REG_INFO(fpu.st[2].f, fpu.st[2].f, ST2) \
	REG_INFO(fpu.st[3].f, fpu.st[3].f, ST3) \
	REG_INFO(fpu.st[4].f, fpu.st[4].f, ST4) \
	REG_INFO(fpu.st[5].f, fpu.st[5].f, ST5) \
	REG_INFO(fpu.st[6].f, fpu.st[6].f, ST6) \
	REG_INFO(fpu.st[7].f, fpu.st[7].f, ST7) \
	REG_INFO(fpu.ip, fpu.ip, FPU_LASTIP) \
	REG_INFO(fpu.cs, fpu.cs, FPU_LASTCS) \
	REG_INFO(fpu.dp, fpu.dp, FPU_LASTDP) \
	REG_INFO(fpu.ds, fpu.ds, FPU_LASTDS) \
	REG_INFO(fpu.fop, fpu.fop, FPU_OPCODE) \
	REG_INFO(fpu.cwd.flat, fpu.cwd.flat, FPU_CONTROL) \
	REG_INFO(fpu.swd.flat, fpu.swd.flat, FPU_STATUS) \
	REG_INFO(fpu.ftw, fpu.ftw, FPU_TAG)

