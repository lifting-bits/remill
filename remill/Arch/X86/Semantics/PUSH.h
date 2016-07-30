/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_X86_SEMANTICS_PUSH_H_
#define REMILL_ARCH_X86_SEMANTICS_PUSH_H_

namespace {

template <typename T>
DEF_HELPER(PushToStack, T val) -> void {
  addr_t op_size = ZExtTo<addr_t>(ByteSizeOf(val));
  addr_t old_xsp = Read(REG_XSP);
  addr_t new_xsp = USub(old_xsp, op_size);
  Write(WritePtr<T>(new_xsp), val);
  Write(REG_XSP, new_xsp);
}

template <typename S1>
DEF_SEM(PUSH, S1 src1) {
  PushToStack(state, memory, Read(src1));
}

}  // namespace

DEF_ISEL(PUSH_GPRv_FFr6_16) = PUSH<R16>;
DEF_ISEL_RI32or64(PUSH_GPRv_FFr6, PUSH);

DEF_ISEL(PUSH_GPRv_50_16) = PUSH<R16>;
DEF_ISEL_RI32or64(PUSH_GPRv_50, PUSH);

DEF_ISEL(PUSH_IMMz_16) = PUSH<I16>;
DEF_ISEL_RI32or64(PUSH_IMMz, PUSH);

DEF_ISEL(PUSH_IMMb_16) = PUSH<I16>;
DEF_ISEL_RI32or64(PUSH_IMMb, PUSH);

DEF_ISEL(PUSH_MEMv_16) = PUSH<M16>;
DEF_ISEL_M32or64(PUSH_MEMv, PUSH);


#if 32 == ADDRESS_SIZE_BITS || 1

DEF_ISEL_SEM(PUSHA) {
  uint16_t sp = Read(REG_SP);
  PushToStack<uint16_t>(state, memory, Read(REG_AX));
  PushToStack<uint16_t>(state, memory, Read(REG_CX));
  PushToStack<uint16_t>(state, memory, Read(REG_DX));
  PushToStack<uint16_t>(state, memory, Read(REG_BX));
  PushToStack<uint16_t>(state, memory, sp);
  PushToStack<uint16_t>(state, memory, Read(REG_BP));
  PushToStack<uint16_t>(state, memory, Read(REG_SI));
  PushToStack<uint16_t>(state, memory, Read(REG_DI));
}

DEF_ISEL_SEM(PUSHAD) {
  uint32_t esp = Read(REG_ESP);
  PushToStack<uint32_t>(state, memory, Read(REG_EAX));
  PushToStack<uint32_t>(state, memory, Read(REG_ECX));
  PushToStack<uint32_t>(state, memory, Read(REG_EDX));
  PushToStack<uint32_t>(state, memory, Read(REG_EBX));
  PushToStack<uint32_t>(state, memory, esp);
  PushToStack<uint32_t>(state, memory, Read(REG_EBP));
  PushToStack<uint32_t>(state, memory, Read(REG_ESI));
  PushToStack<uint32_t>(state, memory, Read(REG_EDI));
}
#endif

namespace {

static void SerializeFlags(State &state) {
  state.rflag.cf = state.aflag.cf;
  //state.rflag.must_be_1 = 1;
  state.rflag.pf = state.aflag.pf;
  //state.rflag.must_be_0a = 0;
  state.rflag.af = state.aflag.af;
  //state.rflag.must_be_0b = 0;
  state.rflag.zf = state.aflag.zf;
  state.rflag.sf = state.aflag.sf;
  //state.rflag.tf = 0;  // Trap flag (not single-stepping).
  //state.rflag._if = 1;  // Interrupts are enabled (assumes user mode).
  state.rflag.df = state.aflag.df;
  state.rflag.of = state.aflag.of;
  //state.rflag.iopl = 0;  // In user-mode. TODO(pag): Configurable?
  //state.rflag.nt = 0;  // Not running in a nested task (interrupted interrupt).
  //state.rflag.must_be_0c = 0;
  //state.rflag.rf = 0; // Not specifying a resume from a breakpoint.
  //state.rflag.vm = 0;  // Virtual 8086 mode is disabled.
  //state.rflag.ac = 0;  // Assume alignment checking is disabled.
  //state.rflag.vif = 0;  // Virtual interrupts are disabled.
  //state.rflag.vip = 0; // No virtual interrupts are pending.
  //state.rflag.id = 0;  // Disallow `CPUID`.  TODO(pag): Configurable?
  //state.rflag.reserved_eflags = 0;  // bits 22-31.
}

}  // namespace

DEF_ISEL_SEM(PUSHF) {
  SerializeFlags(state);
  PushToStack<uint16_t>(state, memory, TruncTo<uint16_t>(state.rflag.flat));
}

#if 32 == ADDRESS_SIZE_BITS
DEF_ISEL_SEM(PUSHFD) {
  SerializeFlags(state);
  PushToStack<uint32_t>(state, memory, TruncTo<uint32_t>(state.rflag.flat));
}
#else
DEF_ISEL_SEM(PUSHFQ) {
  SerializeFlags(state);
  PushToStack<uint64_t>(state, memory, state.rflag.flat);
}
#endif  // 32 == ADDRESS_SIZE_BITS

/*
759 PUSH PUSH_ES PUSH BASE I86 ATTRIBUTES: FIXED_BASE0 SCALABLE STACKPUSH0
760 PUSH PUSH_CS PUSH BASE I86 ATTRIBUTES: FIXED_BASE0 SCALABLE STACKPUSH0
761 PUSH PUSH_SS PUSH BASE I86 ATTRIBUTES: FIXED_BASE0 SCALABLE STACKPUSH0
762 PUSH PUSH_DS PUSH BASE I86 ATTRIBUTES: FIXED_BASE0 SCALABLE STACKPUSH0
766 PUSH PUSH_FS PUSH BASE I86 ATTRIBUTES: FIXED_BASE0 SCALABLE STACKPUSH0
767 PUSH PUSH_GS PUSH BASE I86 ATTRIBUTES: FIXED_BASE0 SCALABLE STACKPUSH0

 */

#endif  // REMILL_ARCH_X86_SEMANTICS_PUSH_H_

