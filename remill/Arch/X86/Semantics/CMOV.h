/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_X86_SEMANTICS_CMOV_H_
#define REMILL_ARCH_X86_SEMANTICS_CMOV_H_

namespace {

template <typename D, typename S1>
ALWAYS_INLINE static void CMOVcc(bool cond, D dst, S1 src1) {
  if (cond) {
    W(dst) = R(src1);
  }
}

template <typename D, typename S1>
DEF_SEM(CMOVNLE, D dst, S1 src1) {
  const auto cond = !state.aflag.zf && state.aflag.sf == state.aflag.of;
  CMOVcc(cond, dst, src1);
}

template <typename D, typename S1>
DEF_SEM(CMOVNS, D dst, S1 src1) {
  const auto cond = !state.aflag.sf;
  CMOVcc(cond, dst, src1);
}

template <typename D, typename S1>
DEF_SEM(CMOVL, D dst, S1 src1) {
  const auto cond = state.aflag.sf != state.aflag.of;
  CMOVcc(cond, dst, src1);
}

template <typename D, typename S1>
DEF_SEM(CMOVNP, D dst, S1 src1) {
  const auto cond = !state.aflag.pf;
  CMOVcc(cond, dst, src1);
}

template <typename D, typename S1>
DEF_SEM(CMOVNZ, D dst, S1 src1) {
  const auto cond = !state.aflag.zf;
  CMOVcc(cond, dst, src1);
}

template <typename D, typename S1>
DEF_SEM(CMOVNB, D dst, S1 src1) {
  const auto cond = !state.aflag.cf;
  CMOVcc(cond, dst, src1);
}

template <typename D, typename S1>
DEF_SEM(CMOVNO, D dst, S1 src1) {
  const auto cond = !state.aflag.of;
  CMOVcc(cond, dst, src1);
}

template <typename D, typename S1>
DEF_SEM(CMOVNL, D dst, S1 src1) {
  const auto cond = state.aflag.sf == state.aflag.of;
  CMOVcc(cond, dst, src1);
}

template <typename D, typename S1>
DEF_SEM(CMOVNBE, D dst, S1 src1) {
  const auto cond = !state.aflag.cf && !state.aflag.zf;
  CMOVcc(cond, dst, src1);
}

template <typename D, typename S1>
DEF_SEM(CMOVBE, D dst, S1 src1) {
  const auto cond = state.aflag.cf || state.aflag.zf;
  CMOVcc(cond, dst, src1);
}

template <typename D, typename S1>
DEF_SEM(CMOVZ, D dst, S1 src1) {
  const auto cond = state.aflag.zf;
  CMOVcc(cond, dst, src1);
}

template <typename D, typename S1>
DEF_SEM(CMOVP, D dst, S1 src1) {
  const auto cond = state.aflag.pf;
  CMOVcc(cond, dst, src1);
}

template <typename D, typename S1>
DEF_SEM(CMOVS, D dst, S1 src1) {
  const auto cond = state.aflag.sf;
  CMOVcc(cond, dst, src1);
}

template <typename D, typename S1>
DEF_SEM(CMOVO, D dst, S1 src1) {
  const auto cond = state.aflag.of;
  CMOVcc(cond, dst, src1);
}

template <typename D, typename S1>
DEF_SEM(CMOVB, D dst, S1 src1) {
  const auto cond = state.aflag.cf;
  CMOVcc(cond, dst, src1);
}

template <typename D, typename S1>
DEF_SEM(CMOVLE, D dst, S1 src1) {
  const auto cond = state.aflag.zf || (state.aflag.sf != state.aflag.of);
  CMOVcc(cond, dst, src1);
}

}  // namespace

DEF_ISEL_RnW_Mn(CMOVBE_GPRv_MEMv, CMOVBE);
DEF_ISEL_RnW_Rn(CMOVBE_GPRv_GPRv, CMOVBE);
DEF_ISEL_RnW_Mn(CMOVLE_GPRv_MEMv, CMOVLE);
DEF_ISEL_RnW_Rn(CMOVLE_GPRv_GPRv, CMOVLE);
DEF_ISEL_RnW_Mn(CMOVNLE_GPRv_MEMv, CMOVNLE);
DEF_ISEL_RnW_Rn(CMOVNLE_GPRv_GPRv, CMOVNLE);
DEF_ISEL_RnW_Mn(CMOVNP_GPRv_MEMv, CMOVNP);
DEF_ISEL_RnW_Rn(CMOVNP_GPRv_GPRv, CMOVNP);
DEF_ISEL_RnW_Mn(CMOVNZ_GPRv_MEMv, CMOVNZ);
DEF_ISEL_RnW_Rn(CMOVNZ_GPRv_GPRv, CMOVNZ);
DEF_ISEL_RnW_Mn(CMOVNS_GPRv_MEMv, CMOVNS);
DEF_ISEL_RnW_Rn(CMOVNS_GPRv_GPRv, CMOVNS);
DEF_ISEL_RnW_Mn(CMOVNO_GPRv_MEMv, CMOVNO);
DEF_ISEL_RnW_Rn(CMOVNO_GPRv_GPRv, CMOVNO);
DEF_ISEL_RnW_Mn(CMOVNL_GPRv_MEMv, CMOVNL);
DEF_ISEL_RnW_Rn(CMOVNL_GPRv_GPRv, CMOVNL);
DEF_ISEL_RnW_Mn(CMOVNB_GPRv_MEMv, CMOVNB);
DEF_ISEL_RnW_Rn(CMOVNB_GPRv_GPRv, CMOVNB);
DEF_ISEL_RnW_Mn(CMOVO_GPRv_MEMv, CMOVO);
DEF_ISEL_RnW_Rn(CMOVO_GPRv_GPRv, CMOVO);
DEF_ISEL_RnW_Mn(CMOVZ_GPRv_MEMv, CMOVZ);
DEF_ISEL_RnW_Rn(CMOVZ_GPRv_GPRv, CMOVZ);
DEF_ISEL_RnW_Mn(CMOVP_GPRv_MEMv, CMOVP);
DEF_ISEL_RnW_Rn(CMOVP_GPRv_GPRv, CMOVP);
DEF_ISEL_RnW_Mn(CMOVS_GPRv_MEMv, CMOVS);
DEF_ISEL_RnW_Rn(CMOVS_GPRv_GPRv, CMOVS);
DEF_ISEL_RnW_Mn(CMOVL_GPRv_MEMv, CMOVL);
DEF_ISEL_RnW_Rn(CMOVL_GPRv_GPRv, CMOVL);
DEF_ISEL_RnW_Mn(CMOVB_GPRv_MEMv, CMOVB);
DEF_ISEL_RnW_Rn(CMOVB_GPRv_GPRv, CMOVB);
DEF_ISEL_RnW_Mn(CMOVNBE_GPRv_MEMv, CMOVNBE);
DEF_ISEL_RnW_Rn(CMOVNBE_GPRv_GPRv, CMOVNBE);

DEF_ISEL(FCMOVNU_ST0_X87_80) = CMOVNP<RF80W, RF80>;
DEF_ISEL(FCMOVNB_ST0_X87_80) = CMOVNB<RF80W, RF80>;
DEF_ISEL(FCMOVNE_ST0_X87_80) = CMOVNZ<RF80W, RF80>;
DEF_ISEL(FCMOVBE_ST0_X87_80) = CMOVBE<RF80W, RF80>;
DEF_ISEL(FCMOVNBE_ST0_X87_80) = CMOVNBE<RF80W, RF80>;
DEF_ISEL(FCMOVU_ST0_X87_80) = CMOVP<RF80W, RF80>;
DEF_ISEL(FCMOVE_ST0_X87_80) = CMOVZ<RF80W, RF80>;
DEF_ISEL(FCMOVB_ST0_X87_80) = CMOVB<RF80W, RF80>;

#endif  // REMILL_ARCH_X86_SEMANTICS_CMOV_H_
