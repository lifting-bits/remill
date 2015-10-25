/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

namespace {

template <typename T>
INSTR_ATTRIBS
static void CALL(State *state, T target_pc) {
  *state->gpr.rsp.ptr-- = state->gpr.rip.full;
  state->gpr.rip.full = static_cast<uintptr_t>(target_pc);
}

template <typename T>
INSTR_ATTRIBS
static void INDIRECT_CALL(State *state, T *target_pc) {
  *state->gpr.rsp.ptr-- = state->gpr.rip.full;
  state->gpr.rip.full = static_cast<uintptr_t>(*target_pc);
}

INSTR_ATTRIBS
static void RET_IMM(State *state, IMM16 bytes) {
  state->gpr.rip.full = *state->gpr.rsp.ptr++;
  state->gpr.rsp.full += bytes;
}

INSTR_ATTRIBS
static void RET(State *state) {
  state->gpr.rip.full = *state->gpr.rsp.ptr++;
}

}  // namespace

DEF_INSTR(CALL_NEAR_RELBRz_8) = CALL<uintptr_t>;
DEF_INSTR(CALL_NEAR_RELBRz_16) = CALL<uintptr_t>;
DEF_INSTR(CALL_NEAR_RELBRz_32) = CALL<uintptr_t>;
DEF_INSTR(CALL_NEAR_RELBRz_64) = CALL<uintptr_t>;

DEF_INSTR(CALL_NEAR_RELBRd_32) = CALL<uintptr_t>;
DEF_INSTR(CALL_NEAR_RELBRd_64) = CALL<uintptr_t>;

DEF_INSTR(CALL_NEAR_MEMv_32) = INDIRECT_CALL<uint32_t>;
DEF_INSTR(CALL_NEAR_MEMv_64) = INDIRECT_CALL<uintptr_t>;

DEF_INSTR(CALL_NEAR_GPRv_8) = CALL<R8>;
DEF_INSTR(CALL_NEAR_GPRv_16) = CALL<R16>;
DEF_INSTR(CALL_NEAR_GPRv_32) = CALL<R32>;
DEF_INSTR(CALL_NEAR_GPRv_64) = CALL<R64>;

/*
352 CALL_FAR CALL_FAR_MEMp2 CALL BASE I86 ATTRIBUTES: FAR_XFER FIXED_BASE1 NOTSX SCALABLE STACKPUSH1
353 CALL_FAR CALL_FAR_PTRp_IMMw CALL BASE I86 ATTRIBUTES: FAR_XFER FIXED_BASE0 NOTSX SCALABLE STACKPUSH0

728 IRETD IRETD RET BASE I386 ATTRIBUTES: FIXED_BASE0 NOTSX SCALABLE STACKPOP0
*/


DEF_INSTR(RET_NEAR_IMMw_16) = RET_IMM;
DEF_INSTR(RET_NEAR_IMMw_32) = RET_IMM;
DEF_INSTR(RET_NEAR_IMMw_64) = RET_IMM;

DEF_INSTR(RET_NEAR_16) = RET;
DEF_INSTR(RET_NEAR_32) = RET;
DEF_INSTR(RET_NEAR_64) = RET;

/*
1073 RET_FAR RET_FAR_IMMw RET BASE I86 ATTRIBUTES: FAR_XFER FIXED_BASE0 NOTSX SCALABLE STACKPOP0
1074 RET_FAR RET_FAR RET BASE I86 ATTRIBUTES: FAR_XFER FIXED_BASE0 NOTSX SCALABLE STACKPOP0
1666 IRETQ IRETQ RET LONGMODE LONGMODE ATTRIBUTES: FIXED_BASE0 NOTSX SCALABLE STACKPOP0
1784 IRET IRET RET BASE I86 ATTRIBUTES: FIXED_BASE0 NOTSX SCALABLE STACKPOP0
*/
