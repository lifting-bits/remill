/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

namespace {

// TODO(pag): Evaluate branch-free variants. Things to evaluate:
//            - Do branch-free conditionals lead to better native code
//              generation?
//            - Do branch-free conditionals lead to better flag lifetime
//              analysis.
//            - Do branch-free conditionals make it easier or harder to
//              reason about the path condition using an SMT solver (e.g.
//              XOR operations might make things harder rather than easier).

DEF_SEM(JNLE, PC taken_rip) {
  const auto cond = !state.aflag.zf && state.aflag.cf == state.aflag.pf;
  IF_NOT_TRANSPARENT( CLEAR_AFLAGS(); )
  state.gpr.rip.full = cond ? taken_rip : state.gpr.rip.full;
}

DEF_SEM(JNS, PC taken_rip) {
  const auto cond = !state.aflag.sf;
  IF_NOT_TRANSPARENT( CLEAR_AFLAGS(); )
  state.gpr.rip.full = cond ? taken_rip : state.gpr.rip.full;
}

DEF_SEM(JL, PC taken_rip) {
  const auto cond = state.aflag.sf != state.aflag.of;
  IF_NOT_TRANSPARENT( CLEAR_AFLAGS(); )
  state.gpr.rip.full = cond ? taken_rip : state.gpr.rip.full;
}

DEF_SEM(JNP, PC taken_rip) {
  const auto cond = !state.aflag.pf;
  IF_NOT_TRANSPARENT( CLEAR_AFLAGS(); )
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JNZ, PC taken_rip) {
  const auto cond = !state.aflag.zf;
  IF_NOT_TRANSPARENT( CLEAR_AFLAGS(); )
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JNB, PC taken_rip) {
  const auto cond = !state.aflag.cf;
  IF_NOT_TRANSPARENT( CLEAR_AFLAGS(); )
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JNO, PC taken_rip) {
  const auto cond = !state.aflag.of;
  IF_NOT_TRANSPARENT( CLEAR_AFLAGS(); )
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JNL, PC taken_rip) {
  const auto cond = state.aflag.sf == state.aflag.of;
  IF_NOT_TRANSPARENT( CLEAR_AFLAGS(); )
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JNBE, PC taken_rip) {
  const auto cond = !state.aflag.cf & !state.aflag.zf;
  IF_NOT_TRANSPARENT( CLEAR_AFLAGS(); )
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JBE, PC taken_rip) {
  const auto cond = state.aflag.cf | state.aflag.zf;
  IF_NOT_TRANSPARENT( CLEAR_AFLAGS(); )
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JZ, PC taken_rip) {
  const auto cond = state.aflag.zf;
  IF_NOT_TRANSPARENT( CLEAR_AFLAGS(); )
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JP, PC taken_rip) {
  const auto cond = state.aflag.pf;
  IF_NOT_TRANSPARENT( CLEAR_AFLAGS(); )
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JS, PC taken_rip) {
  const auto cond = state.aflag.sf;
  IF_NOT_TRANSPARENT( CLEAR_AFLAGS(); )
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JO, PC taken_rip) {
  const auto cond = state.aflag.of;
  IF_NOT_TRANSPARENT( CLEAR_AFLAGS(); )
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JB, PC taken_rip) {
  const auto cond = state.aflag.cf;
  IF_NOT_TRANSPARENT( CLEAR_AFLAGS(); )
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JLE, PC taken_rip) {
  const auto cond = state.aflag.zf | (state.aflag.sf ^ state.aflag.of);
  IF_NOT_TRANSPARENT( CLEAR_AFLAGS(); )
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JCXZ, PC taken_rip) {
  const auto cond = !state.gpr.rcx.word;
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JECXZ, PC taken_rip) {
  const auto cond = !state.gpr.rcx.dword;
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JRCXZ, PC taken_rip) {
  const auto cond = !state.gpr.rcx.full;
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
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
