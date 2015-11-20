/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

namespace {

DEF_SEM(JNLE, PC taken_rip) {
  const auto cond = !state.aflag.zf & !(state.aflag.cf ^ state.aflag.pf);
  CLEAR_AFLAGS();
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JNS, PC taken_rip) {
  const auto cond = !state.aflag.sf;
  CLEAR_AFLAGS();
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JL, PC taken_rip) {
  const auto cond = state.aflag.sf != state.aflag.of;
  CLEAR_AFLAGS();
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JNP, PC taken_rip) {
  const auto cond = !state.aflag.pf;
  CLEAR_AFLAGS();
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JNZ, PC taken_rip) {
  const auto cond = !state.aflag.zf;
  CLEAR_AFLAGS();
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JNB, PC taken_rip) {
  const auto cond = !state.aflag.cf;
  CLEAR_AFLAGS();
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JNO, PC taken_rip) {
  const auto cond = !state.aflag.of;
  CLEAR_AFLAGS();
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JNL, PC taken_rip) {
  const auto cond = state.aflag.sf == state.aflag.of;
  CLEAR_AFLAGS();
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JNBE, PC taken_rip) {
  const auto cond = !state.aflag.cf & !state.aflag.zf;
  CLEAR_AFLAGS();
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JBE, PC taken_rip) {
  const auto cond = state.aflag.cf | state.aflag.zf;
  CLEAR_AFLAGS();
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JZ, PC taken_rip) {
  const auto cond = state.aflag.zf;
  CLEAR_AFLAGS();
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JP, PC taken_rip) {
  const auto cond = state.aflag.pf;
  CLEAR_AFLAGS();
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JS, PC taken_rip) {
  const auto cond = state.aflag.sf;
  CLEAR_AFLAGS();
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JO, PC taken_rip) {
  const auto cond = state.aflag.of;
  CLEAR_AFLAGS();
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JB, PC taken_rip) {
  const auto cond = state.aflag.cf;
  CLEAR_AFLAGS();
  if (cond) {
    state.gpr.rip.full = taken_rip;
  }
}

DEF_SEM(JLE, PC taken_rip) {
  const auto cond = state.aflag.zf | (state.aflag.sf ^ state.aflag.of);
  CLEAR_AFLAGS();
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

DEF_ISEL_32UP(JNLE_RELBRb, JNLE);
DEF_ISEL_32UP(JNLE_RELBRz, JNLE);
DEF_ISEL_32UP(JNLE_RELBRd, JNLE);

DEF_ISEL_32UP(JNS_RELBRb, JNS);
DEF_ISEL_32UP(JNS_RELBRz, JNS);
DEF_ISEL_32UP(JNS_RELBRd, JNS);

DEF_ISEL_32UP(JL_RELBRb, JL);
DEF_ISEL_32UP(JL_RELBRz, JL);
DEF_ISEL_32UP(JL_RELBRd, JL);

DEF_ISEL_32UP(JNP_RELBRb, JNP);
DEF_ISEL_32UP(JNP_RELBRz, JNP);
DEF_ISEL_32UP(JNP_RELBRd, JNP);

DEF_ISEL_32UP(JNZ_RELBRb, JNZ);
DEF_ISEL_32UP(JNZ_RELBRz, JNZ);
DEF_ISEL_32UP(JNZ_RELBRd, JNZ);

DEF_ISEL_32UP(JNB_RELBRb, JNB);
DEF_ISEL_32UP(JNB_RELBRz, JNB);
DEF_ISEL_32UP(JNB_RELBRd, JNB);

DEF_ISEL_32UP(JNO_RELBRb, JNO);
DEF_ISEL_32UP(JNO_RELBRz, JNO);
DEF_ISEL_32UP(JNO_RELBRd, JNO);

DEF_ISEL_32UP(JNL_RELBRb, JNL);
DEF_ISEL_32UP(JNL_RELBRz, JNL);
DEF_ISEL_32UP(JNL_RELBRd, JNL);

DEF_ISEL_32UP(JNBE_RELBRb, JNBE);
DEF_ISEL_32UP(JNBE_RELBRz, JNBE);
DEF_ISEL_32UP(JNBE_RELBRd, JNBE);

DEF_ISEL_32UP(JBE_RELBRb, JBE);
DEF_ISEL_32UP(JBE_RELBRz, JBE);
DEF_ISEL_32UP(JBE_RELBRd, JBE);

DEF_ISEL_32UP(JZ_RELBRb, JZ);
DEF_ISEL_32UP(JZ_RELBRz, JZ);
DEF_ISEL_32UP(JZ_RELBRd, JZ);

DEF_ISEL_32UP(JP_RELBRb, JP);
DEF_ISEL_32UP(JP_RELBRz, JP);
DEF_ISEL_32UP(JP_RELBRd, JP);

DEF_ISEL_32UP(JS_RELBRb, JS);
DEF_ISEL_32UP(JS_RELBRz, JS);
DEF_ISEL_32UP(JS_RELBRd, JS);

DEF_ISEL_32UP(JO_RELBRb, JO);
DEF_ISEL_32UP(JO_RELBRz, JO);
DEF_ISEL_32UP(JO_RELBRd, JO);

DEF_ISEL_32UP(JB_RELBRb, JB);
DEF_ISEL_32UP(JB_RELBRz, JB);
DEF_ISEL_32UP(JB_RELBRd, JB);

DEF_ISEL_32UP(JLE_RELBRb, JLE);
DEF_ISEL_32UP(JLE_RELBRz, JLE);
DEF_ISEL_32UP(JLE_RELBRd, JLE);

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
