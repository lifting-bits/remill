/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_X86_SEMANTICS_X87_H_
#define MCSEMA_ARCH_X86_SEMANTICS_X87_H_

#define PUSH_X87_STACK(x) \
  state.st.element[7].val = state.st.element[6].val ; \
  state.st.element[6].val = state.st.element[5].val ; \
  state.st.element[5].val = state.st.element[4].val ; \
  state.st.element[4].val = state.st.element[3].val ; \
  state.st.element[3].val = state.st.element[2].val ; \
  state.st.element[2].val = state.st.element[1].val ; \
  state.st.element[1].val = state.st.element[0].val ; \
  state.st.element[0].val = x

#define POP_X87_STACK(x) ({\
  auto x ## __LINE__ = state.st.element[0].val ; \
  state.st.element[0].val = state.st.element[1].val ; \
  state.st.element[1].val = state.st.element[2].val ; \
  state.st.element[2].val = state.st.element[3].val ; \
  state.st.element[3].val = state.st.element[4].val ; \
  state.st.element[4].val = state.st.element[5].val ; \
  state.st.element[5].val = state.st.element[6].val ; \
  state.st.element[6].val = state.st.element[7].val ; \
  state.st.element[7].val = __mcsema_undefined_f64(); \
  x; })

DEF_ISEL_SEM(FILD_ST0_MEMmem16int, RF80W, M16 val_) {
  PUSH_X87_STACK(static_cast<double>(static_cast<int16_t>(R(val_))));
}

DEF_ISEL_SEM(FILD_ST0_MEMmem32int, RF80W, M32 val_) {
  PUSH_X87_STACK(static_cast<double>(static_cast<int32_t>(R(val_))));
}

DEF_ISEL_SEM(FILD_ST0_MEMm64int, RF80W, M64 val_) {
  PUSH_X87_STACK(static_cast<double>(static_cast<int64_t>(R(val_))));
}

DEF_ISEL_SEM(FLD_ST0_MEMmem32real, RF80W, MF32 val_) {
  PUSH_X87_STACK(R(val_));
}

DEF_ISEL_SEM(FLD_ST0_MEMm64real, RF80W, MF64 val_) {
  PUSH_X87_STACK(R(val_));
}

DEF_ISEL_SEM(FLD_ST0_MEMmem80real, RF80W, MF80 val_) {
  PUSH_X87_STACK(R(val_));
}

DEF_ISEL_SEM(FLDLN2_ST0, RF80W, RF80 val_) {
  PUSH_X87_STACK(R(val_));
}

DEF_ISEL_SEM(FLD1_ST0, RF80W) {
  PUSH_X87_STACK(1.0);  // +1.0.
}

DEF_ISEL_SEM(FLDZ_ST0, RF80W) {
  PUSH_X87_STACK(0.0);  // +0.0.
}

DEF_ISEL_SEM(FLDLG2_ST0, RF80W) {
  PUSH_X87_STACK(0.30102999566);  // log_10(2).
}

DEF_ISEL_SEM(FLDL2T_ST0, RF80W) {
  PUSH_X87_STACK(3.32192809489);  // log_2(10).
}

DEF_ISEL_SEM(FLDL2E_ST0, RF80W) {
  PUSH_X87_STACK(1.44269504089);  // log_2(e).
}

DEF_ISEL_SEM(FLDPI_ST0, RF80W) {
  PUSH_X87_STACK(3.14159265359);  // pi.
}

/*
1200 FLDENV FLDENV_MEMmem14 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL
1201 FLDENV FLDENV_MEMmem28 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL
1404 FLDCW FLDCW_MEMmem16 X87_ALU X87 X87 ATTRIBUTES: NOTSX X87_CONTROL
 */

#endif  // MCSEMA_ARCH_X86_SEMANTICS_X87_H_
