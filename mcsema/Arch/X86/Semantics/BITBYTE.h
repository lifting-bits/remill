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

namespace {

template <typename S1, typename S2>
DEF_SEM(BTreg, S1 reg_, S2 bit_) {
  typedef typename BaseType<S1>::Type T;
  const T reg = R(reg_);
  const auto bit = R(bit_) % (8 * sizeof(T));
  state.aflag.cf = !!(reg & (T(1) << bit));
}

template <typename S1, typename S2>
DEF_SEM(BTmem, S1 mem_, S2 bit_) {
  typedef typename BaseType<S1>::Type T;
  const auto addr = A(mem_);
  const auto bitoffset = R(bit_);
  enum : T {
    kNumBits = 8 * sizeof(T)
  };
  const auto bit = bitoffset % kNumBits;
  const auto byte = sizeof(T) * (bitoffset / kNumBits);

  Mn<T> byte_mem = {addr + byte};
  state.aflag.cf = !!(R(byte_mem) & (T(1) << bit));
}

template <typename S1, typename S2, typename S3>
DEF_SEM(BTSreg, S1 dst, S2 src_, S3 bit_) {
  typedef typename BaseType<S1>::Type T;
  const T reg = R(src_);
  const auto bit = R(bit_) % (8 * sizeof(T));
  const T mask = T(1) << bit;
  state.aflag.cf = !!(reg & mask);
  W(dst) = reg | mask;
}

template <typename S1, typename S2, typename S3>
DEF_SEM(BTSmem, S2 src_dst_, S3 bit_) {
  typedef typename BaseType<S1>::Type T;
  const auto addr = A(src_dst_);
  const auto bitoffset = R(bit_);

  enum : T {
    kNumBits = 8 * sizeof(T)
  };
  const auto bit = bitoffset % kNumBits;
  const auto byte = sizeof(T) * (bitoffset / kNumBits);

  const T mask = T(1) << bit;
  const addr_t src_dst_addr = addr + byte;

  Mn<T> src_mem = {src_dst_addr};
  const T mem = R(src_mem);
  state.aflag.cf = !!(mem & mask);

  MnW<T> dst_mem = {src_dst_addr};
  W(dst_mem) = mem | mask;
}

template <typename S1, typename S2, typename S3>
DEF_SEM(BTRreg, S1 dst, S2 src_, S3 bit_) {
  typedef typename BaseType<S1>::Type T;
  const T reg = R(src_);
  const auto bit = R(bit_) % (8 * sizeof(T));
  const T mask = T(1) << bit;
  state.aflag.cf = !!(reg & mask);
  W(dst) = reg & ~mask;
}

template <typename S1, typename S2, typename S3>
DEF_SEM(BTRmem, S1, S2 src_dst_, S3 bit_) {
  typedef typename BaseType<S1>::Type T;
  const auto addr = A(src_dst_);
  const auto bitoffset = R(bit_);

  enum : T {
    kNumBits = 8 * sizeof(T)
  };
  const auto bit = bitoffset % kNumBits;
  const auto byte = sizeof(T) * (bitoffset / kNumBits);

  const T mask = T(1) << bit;
  const addr_t src_dst_addr = addr + byte;

  Mn<T> src_mem = {src_dst_addr};
  const T mem = R(src_mem);
  state.aflag.cf = !!(mem & mask);

  MnW<T> dst_mem = {src_dst_addr};
  W(dst_mem) = mem & ~mask;
}


template <typename S1, typename S2, typename S3>
DEF_SEM(BTCreg, S1 dst, S2 src_, S3 bit_) {
  typedef typename BaseType<S1>::Type T;
  const T reg = R(src_);
  const auto bit = R(bit_) % (8 * sizeof(T));
  const T mask = T(1) << bit;
  state.aflag.cf = !!(reg & mask);
  if (state.aflag.cf) {
    W(dst) = reg & ~mask;
  } else {
    W(dst) = reg  | mask;
  }
}

template <typename S1, typename S2, typename S3>
DEF_SEM(BTCmem, S1, S2 src_dst_, S3 bit_) {
  typedef typename BaseType<S1>::Type T;
  const auto addr = A(src_dst_);
  const auto bitoffset = R(bit_);

  enum : T {
    kNumBits = 8 * sizeof(T)
  };
  const auto bit = bitoffset % kNumBits;
  const auto byte = sizeof(T) * (bitoffset / kNumBits);

  const T mask = T(1) << bit;
  const addr_t src_dst_addr = addr + byte;

  Mn<T> src_mem = {src_dst_addr};
  const T mem = R(src_mem);
  state.aflag.cf = !!(mem & mask);

  MnW<T> dst_mem = {src_dst_addr};
  if (state.aflag.cf) {
    W(dst_mem) = mem & ~mask;
  } else {
    W(dst_mem) = mem  | mask;
  }
}

}  // namespace

DEF_ISEL_Mn_In(BT_MEMv_IMMb, BTmem);
DEF_ISEL_Rn_In(BT_GPRv_IMMb, BTreg);
DEF_ISEL_Mn_Rn(BT_MEMv_GPRv, BTmem);
DEF_ISEL_Rn_Rn(BT_GPRv_GPRv, BTreg);

DEF_ISEL_MnW_Mn_In(BTS_MEMv_IMMb, BTSmem);
DEF_ISEL_RnW_Rn_In(BTS_GPRv_IMMb, BTSreg);
DEF_ISEL_MnW_Mn_Rn(BTS_MEMv_GPRv, BTSmem);
DEF_ISEL_RnW_Rn_Rn(BTS_GPRv_GPRv, BTSreg);

DEF_ISEL_MnW_Mn_In(BTR_MEMv_IMMb, BTRmem);
DEF_ISEL_RnW_Rn_In(BTR_GPRv_IMMb, BTRreg);
DEF_ISEL_MnW_Mn_Rn(BTR_MEMv_GPRv, BTRmem);
DEF_ISEL_RnW_Rn_Rn(BTR_GPRv_GPRv, BTRreg);

DEF_ISEL_MnW_Mn_In(BTC_MEMv_IMMb, BTCmem);
DEF_ISEL_RnW_Rn_In(BTC_GPRv_IMMb, BTCreg);
DEF_ISEL_MnW_Mn_Rn(BTC_MEMv_GPRv, BTCmem);
DEF_ISEL_RnW_Rn_Rn(BTC_GPRv_GPRv, BTCreg);

#endif  // MCSEMA_ARCH_X86_SEMANTICS_BITBYTE_H_
