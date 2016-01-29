/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_X86_SEMANTICS_CALL_RET_H_
#define MCSEMA_ARCH_X86_SEMANTICS_CALL_RET_H_

namespace {

template <typename T>
DEF_SEM(CALL, T target_pc) {
  IF_NOT_TRANSPARENT( CLEAR_AFLAGS(); )
  W(state.gpr.rsp) -= sizeof(R(state.gpr.rsp));
  MnW<PC> sp = {R(state.gpr.rsp)};
  W(sp) = next_pc;
  W(state.gpr.rip) = R(target_pc);
}

DEF_SEM(RET_IMM, I16 bytes) {
  IF_NOT_TRANSPARENT( CLEAR_AFLAGS(); )
  Mn<PC> ret_addr_loc = {R(state.gpr.rsp)};
  const PC ret_addr = R(ret_addr_loc);
  W(state.gpr.rip) = ret_addr;
  W(state.gpr.rsp) = R(state.gpr.rsp) + R(bytes) + sizeof(PC);
}

template <typename T>
T POP(State &state) {
  Mn<T> pop_addr = {R(state.gpr.rsp)};
  const T pop_val = R(pop_addr);
  W(state.gpr.rsp) = R(state.gpr.rsp) + sizeof(T);
  return pop_val;
}

DEF_SEM(RET) {
  IF_NOT_TRANSPARENT( CLEAR_AFLAGS(); )
  W(state.gpr.rip) = POP<PC>(state);
}

}  // namespace

DEF_ISEL_32or64(CALL_NEAR_RELBRd, CALL<PC>);
DEF_ISEL_32or64(CALL_NEAR_RELBRz, CALL<PC>);

IF_32BIT( DEF_ISEL(CALL_NEAR_MEMv_16) = CALL<M16>; )
IF_32BIT( DEF_ISEL(CALL_NEAR_MEMv_32) = CALL<M32>; )
IF_64BIT( DEF_ISEL(CALL_NEAR_MEMv_64) = CALL<M64>; )

IF_32BIT( DEF_ISEL(CALL_NEAR_GPRv_16) = CALL<R16>; )
IF_32BIT( DEF_ISEL(CALL_NEAR_GPRv_32) = CALL<R32>; )
IF_64BIT( DEF_ISEL(CALL_NEAR_GPRv_64) = CALL<R64>; )

/*
352 CALL_FAR CALL_FAR_MEMp2 CALL BASE I86 ATTRIBUTES: FAR_XFER FIXED_BASE1 NOTSX SCALABLE STACKPUSH1
353 CALL_FAR CALL_FAR_PTRp_IMMw CALL BASE I86 ATTRIBUTES: FAR_XFER FIXED_BASE0 NOTSX SCALABLE STACKPUSH0

728 IRETD IRETD RET BASE I386 ATTRIBUTES: FIXED_BASE0 NOTSX SCALABLE STACKPOP0
*/

DEF_ISEL_32or64(RET_NEAR_IMMw, RET_IMM);
DEF_ISEL_32or64(RET_NEAR, RET);

/*
1073 RET_FAR RET_FAR_IMMw RET BASE I86 ATTRIBUTES: FAR_XFER FIXED_BASE0 NOTSX SCALABLE STACKPOP0
1074 RET_FAR RET_FAR RET BASE I86 ATTRIBUTES: FAR_XFER FIXED_BASE0 NOTSX SCALABLE STACKPOP0
1666 IRETQ IRETQ RET LONGMODE LONGMODE ATTRIBUTES: FIXED_BASE0 NOTSX SCALABLE STACKPOP0
1784 IRET IRET RET BASE I86 ATTRIBUTES: FIXED_BASE0 NOTSX SCALABLE STACKPOP0
*/

DEF_ISEL_SEM(IRETD_32) {
  W(state.gpr.rip) = POP<uint32_t>(state);
  W(state.seg.cs) = static_cast<uint16_t>(POP<uint32_t>(state));

  Flags flags;
  flags.flat = POP<uint32_t>(state);
  state.aflag.af = flags.af;
  state.aflag.cf = flags.cf;
  state.aflag.df = flags.df;
  state.aflag.of = flags.of;
  state.aflag.pf = flags.pf;
  state.aflag.sf = flags.sf;
  state.aflag.zf = flags.zf;

  // TODO(pag): Hrmmmm.
}

#if 64 == ADDRESS_SIZE_BITS
DEF_ISEL_SEM(IRETQ_64) {
  W(state.gpr.rip) = POP<uint64_t>(state);
  W(state.seg.cs) = static_cast<uint16_t>(POP<uint64_t>(state));

  Flags flags;
  flags.flat = POP<uint64_t>(state);
  state.aflag.af = flags.af;
  state.aflag.cf = flags.cf;
  state.aflag.df = flags.df;
  state.aflag.of = flags.of;
  state.aflag.pf = flags.pf;
  state.aflag.sf = flags.sf;
  state.aflag.zf = flags.zf;

  // TODO(pag): Hrmmmm.
}
#endif  // 64 == ADDRESS_SIZE_BITS

#endif  // MCSEMA_ARCH_X86_SEMANTICS_CALL_RET_H_
