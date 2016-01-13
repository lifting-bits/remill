/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_X86_SEMANTICS_COND_BR_H_
#define MCSEMA_ARCH_X86_SEMANTICS_COND_BR_H_

namespace {

// TODO(pag): Evaluate branch-free variants. Things to evaluate:
//            - Do branch-free conditionals lead to better native code
//              generation?
//            - Do branch-free conditionals lead to better flag lifetime
//              analysis.
//            - Do branch-free conditionals make it easier or harder to
//              reason about the path condition using an SMT solver (e.g.
//              XOR operations might make things harder rather than easier).

DEF_SEM(JNLE, PC target_pc) {
  const auto cond = !state.aflag.zf && state.aflag.cf == state.aflag.pf;
  W(state.gpr.rip) = cond ? target_pc : next_pc;
}

DEF_SEM(JNS, PC target_pc) {
  const auto cond = !state.aflag.sf;
  W(state.gpr.rip) = cond ? target_pc : next_pc;
}

DEF_SEM(JL, PC target_pc) {
  const auto cond = state.aflag.sf != state.aflag.of;
  W(state.gpr.rip) = cond ? target_pc : next_pc;
}

DEF_SEM(JNP, PC target_pc) {
  const auto cond = !state.aflag.pf;
  W(state.gpr.rip) = cond ? target_pc : next_pc;
}

DEF_SEM(JNZ, PC target_pc) {
  const auto cond = !state.aflag.zf;
  W(state.gpr.rip) = cond ? target_pc : next_pc;
}

DEF_SEM(JNB, PC target_pc) {
  const auto cond = !state.aflag.cf;
  W(state.gpr.rip) = cond ? target_pc : next_pc;
}

DEF_SEM(JNO, PC target_pc) {
  const auto cond = !state.aflag.of;
  W(state.gpr.rip) = cond ? target_pc : next_pc;
}

DEF_SEM(JNL, PC target_pc) {
  const auto cond = state.aflag.sf == state.aflag.of;
  W(state.gpr.rip) = cond ? target_pc : next_pc;
}

DEF_SEM(JNBE, PC target_pc) {
  const auto cond = !state.aflag.cf & !state.aflag.zf;
  W(state.gpr.rip) = cond ? target_pc : next_pc;
}

DEF_SEM(JBE, PC target_pc) {
  const auto cond = state.aflag.cf | state.aflag.zf;
  W(state.gpr.rip) = cond ? target_pc : next_pc;
}

DEF_SEM(JZ, PC target_pc) {
  const auto cond = state.aflag.zf;
  W(state.gpr.rip) = cond ? target_pc : next_pc;
}

DEF_SEM(JP, PC target_pc) {
  const auto cond = state.aflag.pf;
  W(state.gpr.rip) = cond ? target_pc : next_pc;
}

DEF_SEM(JS, PC target_pc) {
  const auto cond = state.aflag.sf;
  W(state.gpr.rip) = cond ? target_pc : next_pc;
}

DEF_SEM(JO, PC target_pc) {
  const auto cond = state.aflag.of;
  W(state.gpr.rip) = cond ? target_pc : next_pc;
}

DEF_SEM(JB, PC target_pc) {
  const auto cond = state.aflag.cf;
  W(state.gpr.rip) = cond ? target_pc : next_pc;
}

DEF_SEM(JLE, PC target_pc) {
  const auto cond = state.aflag.zf | (state.aflag.sf ^ state.aflag.of);
  W(state.gpr.rip) = cond ? target_pc : next_pc;
}

DEF_SEM(JCXZ, PC target_pc) {
  const auto cond = !state.gpr.rcx.word;
  W(state.gpr.rip) = cond ? target_pc : next_pc;
}

DEF_SEM(JECXZ, PC target_pc) {
  const auto cond = !state.gpr.rcx.dword;
  W(state.gpr.rip) = cond ? target_pc : next_pc;
}

DEF_SEM(JRCXZ, PC target_pc) {
  const auto cond = !R(state.gpr.rcx);
  W(state.gpr.rip) = cond ? target_pc : next_pc;
}

} // namespace

DEF_ISEL_32or64(JNLE_RELBRb, JNLE);
DEF_ISEL_32or64(JNLE_RELBRz, JNLE);
DEF_ISEL_32or64(JNLE_RELBRd, JNLE);

DEF_ISEL_32or64(JNS_RELBRb, JNS);
DEF_ISEL_32or64(JNS_RELBRz, JNS);
DEF_ISEL_32or64(JNS_RELBRd, JNS);

DEF_ISEL_32or64(JL_RELBRb, JL);
DEF_ISEL_32or64(JL_RELBRz, JL);
DEF_ISEL_32or64(JL_RELBRd, JL);

DEF_ISEL_32or64(JNP_RELBRb, JNP);
DEF_ISEL_32or64(JNP_RELBRz, JNP);
DEF_ISEL_32or64(JNP_RELBRd, JNP);

DEF_ISEL_32or64(JNZ_RELBRb, JNZ);
DEF_ISEL_32or64(JNZ_RELBRz, JNZ);
DEF_ISEL_32or64(JNZ_RELBRd, JNZ);

DEF_ISEL_32or64(JNB_RELBRb, JNB);
DEF_ISEL_32or64(JNB_RELBRz, JNB);
DEF_ISEL_32or64(JNB_RELBRd, JNB);

DEF_ISEL_32or64(JNO_RELBRb, JNO);
DEF_ISEL_32or64(JNO_RELBRz, JNO);
DEF_ISEL_32or64(JNO_RELBRd, JNO);

DEF_ISEL_32or64(JNL_RELBRb, JNL);
DEF_ISEL_32or64(JNL_RELBRz, JNL);
DEF_ISEL_32or64(JNL_RELBRd, JNL);

DEF_ISEL_32or64(JNBE_RELBRb, JNBE);
DEF_ISEL_32or64(JNBE_RELBRz, JNBE);
DEF_ISEL_32or64(JNBE_RELBRd, JNBE);

DEF_ISEL_32or64(JBE_RELBRb, JBE);
DEF_ISEL_32or64(JBE_RELBRz, JBE);
DEF_ISEL_32or64(JBE_RELBRd, JBE);

DEF_ISEL_32or64(JZ_RELBRb, JZ);
DEF_ISEL_32or64(JZ_RELBRz, JZ);
DEF_ISEL_32or64(JZ_RELBRd, JZ);

DEF_ISEL_32or64(JP_RELBRb, JP);
DEF_ISEL_32or64(JP_RELBRz, JP);
DEF_ISEL_32or64(JP_RELBRd, JP);

DEF_ISEL_32or64(JS_RELBRb, JS);
DEF_ISEL_32or64(JS_RELBRz, JS);
DEF_ISEL_32or64(JS_RELBRd, JS);

DEF_ISEL_32or64(JO_RELBRb, JO);
DEF_ISEL_32or64(JO_RELBRz, JO);
DEF_ISEL_32or64(JO_RELBRd, JO);

DEF_ISEL_32or64(JB_RELBRb, JB);
DEF_ISEL_32or64(JB_RELBRz, JB);
DEF_ISEL_32or64(JB_RELBRd, JB);

DEF_ISEL_32or64(JLE_RELBRb, JLE);
DEF_ISEL_32or64(JLE_RELBRz, JLE);
DEF_ISEL_32or64(JLE_RELBRd, JLE);

DEF_ISEL(JRCXZ_RELBRb_16) = JCXZ;
DEF_ISEL(JRCXZ_RELBRb_32) = JECXZ;
DEF_ISEL(JRCXZ_RELBRb_64) = JRCXZ;

/*
522 XEND XEND COND_BR RTM RTM ATTRIBUTES:

585 LOOPNE LOOPNE_RELBRb COND_BR BASE I86 ATTRIBUTES:
586 LOOPNE LOOPNE_RELBRb COND_BR BASE I86 ATTRIBUTES:
587 LOOPNE LOOPNE_RELBRb COND_BR BASE I86 ATTRIBUTES:
588 LOOPNE LOOPNE_RELBRb COND_BR BASE I86 ATTRIBUTES:

714 LOOP LOOP_RELBRb COND_BR BASE I86 ATTRIBUTES:
875 LOOPE LOOPE_RELBRb COND_BR BASE I86 ATTRIBUTES:
876 LOOPE LOOPE_RELBRb COND_BR BASE I86 ATTRIBUTES:
877 LOOPE LOOPE_RELBRb COND_BR BASE I86 ATTRIBUTES:
878 LOOPE LOOPE_RELBRb COND_BR BASE I86 ATTRIBUTES:

1465 XBEGIN XBEGIN_RELBRz COND_BR RTM RTM ATTRIBUTES: SCALABLE
 */

#endif  // MCSEMA_ARCH_X86_SEMANTICS_COND_BR_H_
