/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_X86_SEMANTICS_POP_H_
#define MCSEMA_ARCH_X86_SEMANTICS_POP_H_

namespace {

template <typename T>
T PopValue(State &state) {
  Mn<T> pop_addr = {A(state.gpr.rsp)};
  const T pop_val = R(pop_addr);
  W(state.gpr.rsp) = R(state.gpr.rsp) + sizeof(T);
  return pop_val;
}

// Note: Special handling of `dst` when it has the form `POP [xSP + ...]`
//       is handled in the arch-specific instruction operand lifter.
//
//       The case of `POP xSP` is correctly handled without special casing.
template <typename D>
DEF_SEM(POP, D dst) {
  typedef typename BaseType<D>::Type T;
  W(dst) = PopValue<T>(state);
}

}  // namespace

DEF_ISEL(POP_GPRv_8F_16) = POP<R16W>;
DEF_ISEL_R32or64W(POP_GPRv_8F, POP);

DEF_ISEL(POP_GPRv_51_16) = POP<R16W>;
DEF_ISEL_R32or64W(POP_GPRv_51, POP);

DEF_ISEL(POP_MEMv_16) = POP<M16W>;
DEF_ISEL_M32or64W(POP_MEMv, POP);

#if 32 == ADDRESS_SIZE_BITS
DEF_ISEL_SEM(POPA) {
  W(state.gpr.rdi.word) = PopValue<uint16_t>(state);
  W(state.gpr.rsi.word) = PopValue<uint16_t>(state);
  W(state.gpr.rbp.word) = PopValue<uint16_t>(state);
  (void) PopValue<uint16_t>(state);  // Ignore SP.
  W(state.gpr.rbx.word) = PopValue<uint16_t>(state);
  W(state.gpr.rdx.word) = PopValue<uint16_t>(state);
  W(state.gpr.rcx.word) = PopValue<uint16_t>(state);
  W(state.gpr.rax.word) = PopValue<uint16_t>(state);

}
DEF_ISEL_SEM(POPAD) {
  W(state.gpr.rdi) = PopValue<uint32_t>(state);
  W(state.gpr.rsi) = PopValue<uint32_t>(state);
  W(state.gpr.rbp) = PopValue<uint32_t>(state);
  (void) PopValue<uint32_t>(state);  // Ignore ESP.
  W(state.gpr.rbx) = PopValue<uint32_t>(state);
  W(state.gpr.rdx) = PopValue<uint32_t>(state);
  W(state.gpr.rcx) = PopValue<uint32_t>(state);
  W(state.gpr.rax) = PopValue<uint32_t>(state);
}
#endif

DEF_ISEL_SEM(POPF) {
  Flags f;
  f.flat = PopValue<uint16_t>(state);
  state.aflag.af = f.af;
  state.aflag.cf = f.cf;
  state.aflag.df = f.df;
  state.aflag.of = f.of;
  state.aflag.pf = f.pf;
  state.aflag.sf = f.sf;
  state.aflag.zf = f.zf;
}

#if 32 == ADDRESS_SIZE_BITS
DEF_ISEL_SEM(POPFD) {
  Flags f;
  f.flat = PopValue<uint32_t>(state);
  state.aflag.af = f.af;
  state.aflag.cf = f.cf;
  state.aflag.df = f.df;
  state.aflag.of = f.of;
  state.aflag.pf = f.pf;
  state.aflag.sf = f.sf;
  state.aflag.zf = f.zf;
}
#else
DEF_ISEL_SEM(POPFQ) {
  Flags f;
  f.flat = PopValue<uint64_t>(state);
  state.aflag.af = f.af;
  state.aflag.cf = f.cf;
  state.aflag.df = f.df;
  state.aflag.of = f.of;
  state.aflag.pf = f.pf;
  state.aflag.sf = f.sf;
  state.aflag.zf = f.zf;
}
#endif  // 32 == ADDRESS_SIZE_BITS

/*
1391 POP POP_ES POP BASE I86 ATTRIBUTES: FIXED_BASE0 NOTSX SCALABLE STACKPOP0
1392 POP POP_SS POP BASE I86 ATTRIBUTES: FIXED_BASE0 NOTSX SCALABLE STACKPOP0
1393 POP POP_DS POP BASE I86 ATTRIBUTES: FIXED_BASE0 NOTSX SCALABLE STACKPOP0
1395 POP POP_FS POP BASE I86 ATTRIBUTES: FIXED_BASE0 NOTSX SCALABLE STACKPOP0
1396 POP POP_GS POP BASE I86 ATTRIBUTES: FIXED_BASE0 NOTSX SCALABLE STACKPOP0
 */

#endif  // MCSEMA_ARCH_X86_SEMANTICS_POP_H_
