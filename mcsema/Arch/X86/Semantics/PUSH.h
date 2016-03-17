/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_X86_SEMANTICS_PUSH_H_
#define MCSEMA_ARCH_X86_SEMANTICS_PUSH_H_

namespace {

template <typename S>
DEF_SEM(PUSH, S val_) {
  typedef typename BaseType<S>::Type T;
  const T pushed_val = R(val_);
  const addr_t sp = R(state.gpr.rsp);
  const addr_t new_sp = sp - sizeof(pushed_val);

  MnW<T> stack = {new_sp};
  W(state.gpr.rsp) = new_sp;
  W(stack) = pushed_val;
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
  auto temp = R(state.gpr.rsp.word);
  PushValue<uint16_t>(state, R(state.gpr.rax.word));
  PushValue<uint16_t>(state, R(state.gpr.rcx.word));
  PushValue<uint16_t>(state, R(state.gpr.rdx.word));
  PushValue<uint16_t>(state, R(state.gpr.rbx.word));
  PushValue<uint16_t>(state, temp);
  PushValue<uint16_t>(state, R(state.gpr.rbp.word));
  PushValue<uint16_t>(state, R(state.gpr.rsi.word));
  PushValue<uint16_t>(state, R(state.gpr.rdi.word));
}

DEF_ISEL_SEM(PUSHAD) {
  auto temp = R(state.gpr.rsp);
  PushValue<uint32_t>(state, R(state.gpr.rax));
  PushValue<uint32_t>(state, R(state.gpr.rcx));
  PushValue<uint32_t>(state, R(state.gpr.rdx));
  PushValue<uint32_t>(state, R(state.gpr.rbx));
  PushValue<uint32_t>(state, temp);
  PushValue<uint32_t>(state, R(state.gpr.rbp));
  PushValue<uint32_t>(state, R(state.gpr.rsi));
  PushValue<uint32_t>(state, R(state.gpr.rdi));
}
#endif

/*
 *     uint32_t cf:1;  // bit 0.
    uint32_t must_be_1:1;
    uint32_t pf:1;
    uint32_t must_be_0a:1;

    uint32_t af:1; // bit 4.
    uint32_t must_be_0b:1;
    uint32_t zf:1;
    uint32_t sf:1;

    uint32_t tf:1;  // bit 8.
    uint32_t _if:1;  // underscore to avoid token clash.
    uint32_t df:1;
    uint32_t of:1;

    uint32_t iopl:2; // A 2-bit field, bits 12-13.
    uint32_t nt:1;
    uint32_t must_be_0c:1;
 */

namespace {

static void SerializeFlags(State &state) {
  state.rflag.cf = state.aflag.cf;
  state.rflag.must_be_1 = 1;
  state.rflag.pf = state.aflag.pf;
  state.rflag.must_be_0a = 0;
  state.rflag.af = state.aflag.af;
  state.rflag.must_be_0b = 0;
  state.rflag.zf = state.aflag.zf;
  state.rflag.sf = state.aflag.sf;
  state.rflag.tf = 0;  // Trap flag (not single-stepping).
  state.rflag._if = 1;  // Interrupts are enabled.
  state.rflag.df = state.aflag.df;
  state.rflag.of = state.aflag.of;
  state.rflag.iopl = 3;  // In user-mode. TODO(pag): Configurable?
  state.rflag.nt = 0;  // Not running in a nested task (interrupted interrupt).
  state.rflag.must_be_0c = 0;
  state.rflag.rf = 0; // Not specifying a resume from a breakpoint.
  state.rflag.vm = 0;
  state.rflag.ac = 0;  // Assume alignment checking is disabled.
  state.rflag.vif = 0;
  state.rflag.vip = 0; // No virtual interrupts are pending.
  state.rflag.id = 0;  // Disallow `CPUID`.  TODO(pag): What is sane here?
  state.rflag.reserved_eflags = 0;  // bits 22-31.
}

}  // namespace

DEF_ISEL_SEM(PUSHF) {
  SerializeFlags(state);
  PushValue<uint16_t>(state, static_cast<uint16_t>(state.rflag.flat));
}

#if 32 == ADDRESS_SIZE_BITS
DEF_ISEL_SEM(PUSHFD) {
  SerializeFlags(state);
  auto eflags = static_cast<uint32_t>(state.rflag.flat);
  PushValue<uint32_t>(state, eflags & 0x00FCFFFFU);
}
#else
DEF_ISEL_SEM(PUSHFQ) {
  SerializeFlags(state);
  PushValue<uint64_t>(state, state.rflag.flat & 0x00FCFFFFU);
}
#endif  // 32 == ADDRESS_SIZE_BITS

/*
759 PUSH PUSH_ES PUSH BASE I86 ATTRIBUTES: FIXED_BASE0 SCALABLE STACKPUSH0
760 PUSH PUSH_CS PUSH BASE I86 ATTRIBUTES: FIXED_BASE0 SCALABLE STACKPUSH0
761 PUSH PUSH_SS PUSH BASE I86 ATTRIBUTES: FIXED_BASE0 SCALABLE STACKPUSH0
762 PUSH PUSH_DS PUSH BASE I86 ATTRIBUTES: FIXED_BASE0 SCALABLE STACKPUSH0
766 PUSH PUSH_FS PUSH BASE I86 ATTRIBUTES: FIXED_BASE0 SCALABLE STACKPUSH0
767 PUSH PUSH_GS PUSH BASE I86 ATTRIBUTES: FIXED_BASE0 SCALABLE STACKPUSH0

1017 ENTER ENTER_IMMw_IMMb MISC BASE I186 ATTRIBUTES: ATT_OPERAND_ORDER_EXCEPTION FIXED_BASE0 SCALABLE STACKPUSH0

 */

#endif  // MCSEMA_ARCH_X86_SEMANTICS_PUSH_H_

