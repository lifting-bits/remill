/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_X86_SEMANTICS_BITBYTE_H_
#define MCSEMA_ARCH_X86_SEMANTICS_BITBYTE_H_

namespace {

template <typename D>
DEF_SEM(SETNLE, D dst) {
  const auto cond = !state.aflag.zf && state.aflag.cf == state.aflag.pf;
  W(dst) = cond;
}

template <typename D>
DEF_SEM(SETNS, D dst) {
  const auto cond = !state.aflag.sf;
  W(dst) = cond;
}

template <typename D>
DEF_SEM(SETL, D dst) {
  const auto cond = state.aflag.sf != state.aflag.of;
  W(dst) = cond;
}

template <typename D>
DEF_SEM(SETNP, D dst) {
  const auto cond = !state.aflag.pf;
  W(dst) = cond;
}

template <typename D>
DEF_SEM(SETNZ, D dst) {
  const auto cond = !state.aflag.zf;
  W(dst) = cond;
}

template <typename D>
DEF_SEM(SETNB, D dst) {
  const auto cond = !state.aflag.cf;
  W(dst) = cond;
}

template <typename D>
DEF_SEM(SETNO, D dst) {
  const auto cond = !state.aflag.of;
  W(dst) = cond;
}

template <typename D>
DEF_SEM(SETNL, D dst) {
  const auto cond = state.aflag.sf == state.aflag.of;
  W(dst) = cond;
}

template <typename D>
DEF_SEM(SETNBE, D dst) {
  const auto cond = !state.aflag.cf & !state.aflag.zf;
  W(dst) = cond;
}

template <typename D>
DEF_SEM(SETBE, D dst) {
  const auto cond = state.aflag.cf | state.aflag.zf;
  W(dst) = cond;
}

template <typename D>
DEF_SEM(SETZ, D dst) {
  const auto cond = state.aflag.zf;
  W(dst) = cond;
}

template <typename D>
DEF_SEM(SETP, D dst) {
  const auto cond = state.aflag.pf;
  W(dst) = cond;
}

template <typename D>
DEF_SEM(SETS, D dst) {
  const auto cond = state.aflag.sf;
  W(dst) = cond;
}

template <typename D>
DEF_SEM(SETO, D dst) {
  const auto cond = state.aflag.of;
  W(dst) = cond;
}

template <typename D>
DEF_SEM(SETB, D dst) {
  const auto cond = state.aflag.cf;
  W(dst) = cond;
}

template <typename D>
DEF_SEM(SETLE, D dst) {
  const auto cond = state.aflag.zf | (state.aflag.sf ^ state.aflag.of);
  W(dst) = cond;
}

}  // namespace
DEF_ISEL(SETB_MEMb) = SETB<M8W>;
DEF_ISEL(SETB_GPR8) = SETB<R8W>;
DEF_ISEL(SETL_MEMb) = SETL<M8W>;
DEF_ISEL(SETL_GPR8) = SETL<R8W>;
DEF_ISEL(SETO_MEMb) = SETO<M8W>;
DEF_ISEL(SETO_GPR8) = SETO<R8W>;
DEF_ISEL(SETP_MEMb) = SETP<M8W>;
DEF_ISEL(SETP_GPR8) = SETP<R8W>;
DEF_ISEL(SETZ_MEMb) = SETZ<M8W>;
DEF_ISEL(SETZ_GPR8) = SETZ<R8W>;
DEF_ISEL(SETS_MEMb) = SETS<M8W>;
DEF_ISEL(SETS_GPR8) = SETS<R8W>;
DEF_ISEL(SETNO_MEMb) = SETNO<M8W>;
DEF_ISEL(SETNO_GPR8) = SETNO<R8W>;
DEF_ISEL(SETNL_MEMb) = SETNL<M8W>;
DEF_ISEL(SETNL_GPR8) = SETNL<R8W>;
DEF_ISEL(SETNB_MEMb) = SETNB<M8W>;
DEF_ISEL(SETNB_GPR8) = SETNB<R8W>;
DEF_ISEL(SETNZ_MEMb) = SETNZ<M8W>;
DEF_ISEL(SETNZ_GPR8) = SETNZ<R8W>;
DEF_ISEL(SETNS_MEMb) = SETNS<M8W>;
DEF_ISEL(SETNS_GPR8) = SETNS<R8W>;
DEF_ISEL(SETNP_MEMb) = SETNP<M8W>;
DEF_ISEL(SETNP_GPR8) = SETNP<R8W>;
DEF_ISEL(SETNBE_MEMb) = SETNBE<M8W>;
DEF_ISEL(SETNBE_GPR8) = SETNBE<R8W>;
DEF_ISEL(SETLE_MEMb) = SETLE<M8W>;
DEF_ISEL(SETLE_GPR8) = SETLE<R8W>;
DEF_ISEL(SETNLE_MEMb) = SETNLE<M8W>;
DEF_ISEL(SETNLE_GPR8) = SETNLE<R8W>;
DEF_ISEL(SETBE_MEMb) = SETBE<M8W>;
DEF_ISEL(SETBE_GPR8) = SETBE<R8W>;

#endif  // MCSEMA_ARCH_X86_SEMANTICS_BITBYTE_H_
