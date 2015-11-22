/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

namespace {

template <typename T>
DEF_SEM(CALL, T target_pc) {
  IF_NOT_TRANSPARENT( CLEAR_AFLAGS(); )
  state.gpr.rsp.full -= sizeof(state.gpr.rsp.full);
  MnW<PC> sp = {state.gpr.rsp.full};
  W(sp) = state.gpr.rip.full;
  state.gpr.rip.full = R(target_pc);
}

DEF_SEM(RET_IMM, I16 bytes) {
  IF_NOT_TRANSPARENT( CLEAR_AFLAGS(); )
  Mn<PC> ret_addr_loc = {state.gpr.rsp.full};
  const PC ret_addr = R(ret_addr_loc);
  W(state.gpr.rip.full) = ret_addr;
  W(state.gpr.rsp.full) = R(state.gpr.rsp.full) + bytes + sizeof(PC);
}

DEF_SEM(RET) {
  IF_NOT_TRANSPARENT( CLEAR_AFLAGS(); )
  Mn<PC> ret_addr_loc = {state.gpr.rsp.full};
  const PC ret_addr = R(ret_addr_loc);
  W(state.gpr.rip.full) = ret_addr;
  W(state.gpr.rsp.full) = R(state.gpr.rsp.full) + sizeof(PC);
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
