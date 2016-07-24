/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_X86_SEMANTICS_CALL_RET_H_
#define REMILL_ARCH_X86_SEMANTICS_CALL_RET_H_

namespace {

template <typename T>
DEF_SEM(CALL, T target_pc) {

  auto target = R(target_pc);
  __remill_barrier_compiler();
  PushValue<PC>(state, __remill_create_program_counter(next_pc));
  W(state.gpr.rip) = target;
}

DEF_SEM(RET_IMM, I16 bytes) {
  Mn<PC> ret_addr_loc = {A(state.gpr.rsp)};
  W(state.gpr.rip) = R(ret_addr_loc);
  W(state.gpr.rsp) = R(state.gpr.rsp) + R(bytes) + sizeof(PC);
}

DEF_SEM(RET) {
  W(state.gpr.rip) = PopValue<PC>(state);
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
  W(state.gpr.rip) = __remill_create_program_counter(PopValue<uint32_t>(state));
  W(state.seg.cs) = static_cast<uint16_t>(PopValue<uint32_t>(state));

  Flags flags;
  flags.flat = PopValue<uint32_t>(state);
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
  W(state.gpr.rip) = __remill_create_program_counter(PopValue<uint64_t>(state));
  W(state.seg.cs) = static_cast<uint16_t>(PopValue<uint64_t>(state));

  Flags flags;
  flags.flat = PopValue<uint64_t>(state);
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

#endif  // REMILL_ARCH_X86_SEMANTICS_CALL_RET_H_
