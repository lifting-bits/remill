/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_X86_SEMANTICS_BINARY_H_
#define MCSEMA_ARCH_X86_SEMANTICS_BINARY_H_

namespace {

template <typename Tag, typename T>
ALWAYS_INLINE void SetFlagsIncDec(State &state, T lhs, T rhs, T res) {
  state.aflag.pf = ParityFlag(res);
  state.aflag.af = AuxCarryFlag(lhs, rhs, res);
  state.aflag.zf = ZeroFlag(res);
  state.aflag.sf = SignFlag(res);
  state.aflag.of = Overflow<Tag>::Flag(lhs, rhs, res);
}

template <typename Tag, typename T>
ALWAYS_INLINE void SetFlagsAddSub(State &state, T lhs, T rhs, T res) {
  state.aflag.cf = Carry<Tag>::Flag(lhs, rhs, res);
  SetFlagsIncDec<Tag>(state, lhs, rhs, res);
}

template <typename D, typename S1, typename S2>
DEF_SEM(ADD, D dst, const S1 src1_, const S2 src2_) {
  typedef typename BaseType<S1>::Type T;  // `D` might be wider than `S1`.
  const T src1 = R(src1_);
  const T src2 = R(src2_);
  const T res = src1 + src2;
  W(dst) = res;
  __mcsema_barrier_compiler();
  SetFlagsAddSub<tag_add>(state, src1, src2, res);
}

template <typename D, typename S1, typename S2>
DEF_SEM(ADD_VFP64, D dst, const S1 src1_, const S2 src2_) {
  typedef typename BaseType<S1>::Type T;  // `D` might be wider than `S1`.
  const T src1 = R(src1_);
  const T src2 = R(src2_);
  W(dst) = src1.doubles + src2.doubles;
}

template <typename D, typename S1, typename S2>
DEF_SEM(ADD_VFP32, D dst, const S1 src1_, const S2 src2_) {
  typedef typename BaseType<S1>::Type T;  // `D` might be wider than `S1`.
  const T src1 = R(src1_);
  const T src2 = R(src2_);
  W(dst) = src1.floats + src2.floats;
}

// Atomic fetch-add.
template <typename MW, typename M, typename RW, typename RT>
DEF_SEM(XADD, MW mdst, const M msrc_, const RW rdst, const RT rsrc_) {
  typedef typename BaseType<RT>::Type T;

  // Our lifter only injects atomic begin/end around memory access instructions
  // but this instruction is a full memory barrier, even when registers are
  // accessed.
  if (IsRegister<RW>::kValue) {
    __mcsema_barrier_store_load();
  }

  const T src1 = R(msrc_);
  const T src2 = R(rsrc_);
  const T res = src1 + src2;
  W(mdst) = res;
  __mcsema_barrier_compiler();
  W(rdst) = src1;
  __mcsema_barrier_compiler();
  SetFlagsAddSub<tag_add>(state, src1, src2, res);
}

template <typename D, typename S1, typename S2>
DEF_SEM(ADDSS, D dst, const S1 src1_, const S2 src2_) {
  auto src1 = R(src1_);
  const auto src2 = R(src2_);
  src1.floats[0] += src2.floats[0];
  W(dst) = src1;
}

template <typename D, typename S1, typename S2>
DEF_SEM(VADDSS, D dst, const S1 src1_, const S2 src2_) {
  const auto src1 = R(src1_);
  const auto src2 = R(src2_);
  W(dst) = float32v4_t{src1.floats[0] + src2.floats[0],
                       src1.floats[1],
                       src1.floats[2],
                       src1.floats[3]};
}

template <typename D, typename S1, typename S2>
DEF_SEM(ADDSD, D dst, const S1 src1_, const S2 src2_) {
  auto src1 = R(src1_);
  const auto src2 = R(src2_);
  src1.doubles[0] += src2.doubles[0];
  W(dst) = src1;
}

template <typename D, typename S1, typename S2>
DEF_SEM(VADDSD, D dst, const S1 src1_, const S2 src2_) {
  const auto src1 = R(src1_);
  const auto src2 = R(src2_);
  W(dst) = float64v2_t{src1.doubles[0] + src2.doubles[0],
                       src1.doubles[1]};
}

}  // namespace

DEF_ISEL(ADD_MEMb_IMMb_80r0) = ADD<M8W, M8, I8>;
DEF_ISEL(ADD_GPR8_IMMb_80r0) = ADD<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(ADD_MEMv_IMMz, ADD);
DEF_ISEL_RnW_Rn_In(ADD_GPRv_IMMz, ADD);
DEF_ISEL(ADD_MEMb_IMMb_82r0) = ADD<M8W, M8, I8>;
DEF_ISEL(ADD_GPR8_IMMb_82r0) = ADD<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(ADD_MEMv_IMMb, ADD);
DEF_ISEL_RnW_Rn_In(ADD_GPRv_IMMb, ADD);
DEF_ISEL(ADD_MEMb_GPR8) = ADD<M8W, M8, R8>;
DEF_ISEL(ADD_GPR8_GPR8_00) = ADD<R8W, R8, R8>;
DEF_ISEL_MnW_Mn_Rn(ADD_MEMv_GPRv, ADD);
DEF_ISEL_RnW_Rn_Rn(ADD_GPRv_GPRv_01, ADD);
DEF_ISEL(ADD_GPR8_MEMb) = ADD<R8W, R8, M8>;
DEF_ISEL(ADD_GPR8_GPR8_02) = ADD<R8W, R8, R8>;
DEF_ISEL_RnW_Rn_Mn(ADD_GPRv_MEMv, ADD);
DEF_ISEL_RnW_Rn_Rn(ADD_GPRv_GPRv_03, ADD);
DEF_ISEL(ADD_AL_IMMb) = ADD<R8W, R8, I8>;
DEF_ISEL_RnW_Rn_In(ADD_OrAX_IMMz, ADD);

DEF_ISEL(XADD_MEMb_GPR8) = XADD<M8W, M8, R8W, R8>;
DEF_ISEL(XADD_GPR8_GPR8) = XADD<R8W, R8, R8W, R8>;
DEF_ISEL_MnW_Mn_RnW_Rn(XADD_MEMv_GPRv, XADD);
DEF_ISEL_RnW_Rn_RnW_Rn(XADD_GPRv_GPRv, XADD);

DEF_ISEL(ADDPS_XMMps_MEMps) = ADD_VFP32<V128W, V128, MV128>;
DEF_ISEL(ADDPS_XMMps_XMMps) = ADD_VFP32<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VADDPS_XMMdq_XMMdq_MEMdq) = ADD_VFP32<VV128W, VV128, MV128>;)
IF_AVX(DEF_ISEL(VADDPS_XMMdq_XMMdq_XMMdq) = ADD_VFP32<VV128W, VV128, VV128>;)
IF_AVX(DEF_ISEL(VADDPS_YMMqq_YMMqq_MEMqq) = ADD_VFP32<VV256W, VV256, MV256>;)
IF_AVX(DEF_ISEL(VADDPS_YMMqq_YMMqq_YMMqq) = ADD_VFP32<VV256W, VV256, VV256>;)

DEF_ISEL(ADDPD_XMMpd_MEMpd) = ADD_VFP64<V128W, V128, MV128>;
DEF_ISEL(ADDPD_XMMpd_XMMpd) = ADD_VFP64<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VADDPD_XMMdq_XMMdq_MEMdq) = ADD_VFP64<VV128W, VV128, MV128>;)
IF_AVX(DEF_ISEL(VADDPD_XMMdq_XMMdq_XMMdq) = ADD_VFP64<VV128W, VV128, VV128>;)
IF_AVX(DEF_ISEL(VADDPD_YMMqq_YMMqq_MEMqq) = ADD_VFP64<VV256W, VV256, MV256>;)
IF_AVX(DEF_ISEL(VADDPD_YMMqq_YMMqq_YMMqq) = ADD_VFP64<VV256W, VV256, VV256>;)

DEF_ISEL(ADDSS_XMMss_MEMss) = ADDSS<V128W, V128, MV32>;
DEF_ISEL(ADDSS_XMMss_XMMss) = ADDSS<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VADDSS_XMMdq_XMMdq_MEMd) = VADDSS<VV128W, VV128, MV32>;)
IF_AVX(DEF_ISEL(VADDSS_XMMdq_XMMdq_XMMd) = VADDSS<VV128W, VV128, VV128>;)

DEF_ISEL(ADDSD_XMMsd_MEMsd) = ADDSD<V128W, V128, MV64>;
DEF_ISEL(ADDSD_XMMss_XMMss) = ADDSD<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VADDSD_XMMdq_XMMdq_MEMq) = VADDSD<VV128W, VV128, MV64>;)
IF_AVX(DEF_ISEL(VADDSD_XMMdq_XMMdq_XMMq) = VADDSD<VV128W, VV128, VV128>;)

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(SUB, D dst, const S1 src1_, const S2 src2_) {
  typedef typename BaseType<S1>::Type T;  // `D` might be wider than `S1`.
  const T src1 = R(src1_);
  const T src2 = R(src2_);
  const T res = src1 - src2;
  W(dst) = res;
  __mcsema_barrier_compiler();
  SetFlagsAddSub<tag_sub>(state, src1, src2, res);
}

template <typename D, typename S1, typename S2>
DEF_SEM(SUB_VFP64, D dst, const S1 src1_, const S2 src2_) {
  typedef typename BaseType<S1>::Type T;  // `D` might be wider than `S1`.
  const T src1 = R(src1_);
  const T src2 = R(src2_);
  W(dst) = src1.doubles - src2.doubles;
}

template <typename D, typename S1, typename S2>
DEF_SEM(SUB_VFP32, D dst, const S1 src1_, const S2 src2_) {
  typedef typename BaseType<S1>::Type T;  // `D` might be wider than `S1`.
  const T src1 = R(src1_);
  const T src2 = R(src2_);
  W(dst) = src1.floats - src2.floats;
}

template <typename D, typename S1, typename S2>
DEF_SEM(SUBSS, D dst, const S1 src1_, const S2 src2_) {
  auto src1 = R(src1_);
  const auto src2 = R(src2_);
  src1.floats[0] -= src2.floats[0];
  W(dst) = src1;
}

template <typename D, typename S1, typename S2>
DEF_SEM(VSUBSS, D dst, const S1 src1_, const S2 src2_) {
  const auto src1 = R(src1_);
  const auto src2 = R(src2_);
  W(dst) = float32v4_t{src1.floats[0] - src2.floats[0],
                       src1.floats[1],
                       src1.floats[2],
                       src1.floats[3]};
}

template <typename D, typename S1, typename S2>
DEF_SEM(SUBSD, D dst, const S1 src1_, const S2 src2_) {
  auto src1 = R(src1_);
  const auto src2 = R(src2_);
  src1.doubles[0] -= src2.doubles[0];
  W(dst) = src1;
}

template <typename D, typename S1, typename S2>
DEF_SEM(VSUBSD, D dst, const S1 src1_, const S2 src2_) {
  const auto src1 = R(src1_);
  const auto src2 = R(src2_);
  W(dst) = float64v2_t{src1.doubles[0] - src2.doubles[0],
                       src1.doubles[1]};
}

}  // namespace

DEF_ISEL(SUB_MEMb_IMMb_80r5) = SUB<M8W, M8, I8>;
DEF_ISEL(SUB_GPR8_IMMb_80r5) = SUB<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(SUB_MEMv_IMMz, SUB);
DEF_ISEL_RnW_Rn_In(SUB_GPRv_IMMz, SUB);
DEF_ISEL(SUB_MEMb_IMMb_82r5) = SUB<M8W, M8, I8>;
DEF_ISEL(SUB_GPR8_IMMb_82r5) = SUB<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(SUB_MEMv_IMMb, SUB);
DEF_ISEL_RnW_Rn_In(SUB_GPRv_IMMb, SUB);
DEF_ISEL(SUB_MEMb_GPR8) = SUB<M8W, M8, I8>;
DEF_ISEL(SUB_GPR8_GPR8_28) = SUB<R8W, R8, R8>;
DEF_ISEL_MnW_Mn_Rn(SUB_MEMv_GPRv, SUB);
DEF_ISEL_RnW_Rn_Rn(SUB_GPRv_GPRv_29, SUB);
DEF_ISEL(SUB_GPR8_GPR8_2A) = SUB<R8W, R8, R8>;
DEF_ISEL(SUB_GPR8_MEMb) = SUB<R8W, R8, M8>;
DEF_ISEL_RnW_Rn_Rn(SUB_GPRv_GPRv_2B, SUB);
DEF_ISEL_RnW_Rn_Mn(SUB_GPRv_MEMv, SUB);
DEF_ISEL(SUB_AL_IMMb) = SUB<R8W, R8, I8>;
DEF_ISEL_RnW_Rn_In(SUB_OrAX_IMMz, SUB);

DEF_ISEL(SUBPS_XMMps_MEMps) = SUB_VFP32<V128W, V128, MV128>;
DEF_ISEL(SUBPS_XMMps_XMMps) = SUB_VFP32<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VSUBPS_XMMdq_XMMdq_MEMdq) = SUB_VFP32<VV128W, VV128, MV128>;)
IF_AVX(DEF_ISEL(VSUBPS_XMMdq_XMMdq_XMMdq) = SUB_VFP32<VV128W, VV128, VV128>;)
IF_AVX(DEF_ISEL(VSUBPS_YMMqq_YMMqq_MEMqq) = SUB_VFP32<VV256W, VV256, MV256>;)
IF_AVX(DEF_ISEL(VSUBPS_YMMqq_YMMqq_YMMqq) = SUB_VFP32<VV256W, VV256, VV256>;)

DEF_ISEL(SUBPD_XMMpd_MEMpd) = SUB_VFP64<V128W, V128, MV128>;
DEF_ISEL(SUBPD_XMMpd_XMMpd) = SUB_VFP64<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VSUBPD_XMMdq_XMMdq_MEMdq) = SUB_VFP64<VV128W, VV128, MV128>;)
IF_AVX(DEF_ISEL(VSUBPD_XMMdq_XMMdq_XMMdq) = SUB_VFP64<VV128W, VV128, VV128>;)
IF_AVX(DEF_ISEL(VSUBPD_YMMqq_YMMqq_MEMqq) = SUB_VFP64<VV256W, VV256, MV256>;)
IF_AVX(DEF_ISEL(VSUBPD_YMMqq_YMMqq_YMMqq) = SUB_VFP64<VV256W, VV256, VV256>;)

DEF_ISEL(SUBSS_XMMss_MEMss) = SUBSS<V128W, V128, MV32>;
DEF_ISEL(SUBSS_XMMss_XMMss) = SUBSS<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VSUBSS_XMMdq_XMMdq_MEMd) = VSUBSS<VV128W, VV128, MV32>;)
IF_AVX(DEF_ISEL(VSUBSS_XMMdq_XMMdq_XMMd) = VSUBSS<VV128W, VV128, VV128>;)

DEF_ISEL(SUBSD_XMMsd_MEMsd) = SUBSD<V128W, V128, MV64>;
DEF_ISEL(SUBSD_XMMss_XMMss) = SUBSD<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VSUBSD_XMMdq_XMMdq_MEMq) = VSUBSD<VV128W, VV128, MV64>;)
IF_AVX(DEF_ISEL(VSUBSD_XMMdq_XMMdq_XMMq) = VSUBSD<VV128W, VV128, VV128>;)

namespace {

template <typename S1, typename S2>
DEF_SEM(CMP, const S1 src1_, const S2 src2_) {
  typedef typename BaseType<S1>::Type T;
  const T src1 = R(src1_);
  const T src2 = R(src2_);
  const T res = src1 - src2;
  __mcsema_barrier_compiler();
  SetFlagsAddSub<tag_sub>(state, src1, src2, res);
}

}  // namespace

DEF_ISEL(CMP_MEMb_IMMb_80r7) = CMP<M8, I8>;
DEF_ISEL(CMP_GPR8_IMMb_80r7) = CMP<R8, I8>;
DEF_ISEL_Mn_In(CMP_MEMv_IMMz, CMP);
DEF_ISEL_Rn_In(CMP_GPRv_IMMz, CMP);
DEF_ISEL(CMP_MEMb_IMMb_82r7) = CMP<M8, I8>;
DEF_ISEL(CMP_GPR8_IMMb_82r7) = CMP<R8, I8>;
DEF_ISEL_Mn_In(CMP_MEMv_IMMb, CMP);
DEF_ISEL_Rn_In(CMP_GPRv_IMMb, CMP);
DEF_ISEL(CMP_MEMb_GPR8) = CMP<M8, I8>;
DEF_ISEL(CMP_GPR8_GPR8_38) = CMP<R8, R8>;
DEF_ISEL_Mn_In(CMP_MEMv_GPRv, CMP);
DEF_ISEL_Rn_Rn(CMP_GPRv_GPRv_39, CMP);
DEF_ISEL(CMP_GPR8_GPR8_3A) = CMP<R8, R8>;
DEF_ISEL(CMP_GPR8_MEMb) = CMP<R8, M8>;
DEF_ISEL_Rn_Rn(CMP_GPRv_GPRv_3B, CMP);
DEF_ISEL_Rn_Mn(CMP_GPRv_MEMv, CMP);
DEF_ISEL(CMP_AL_IMMb) = CMP<R8, I8>;
DEF_ISEL_Rn_In(CMP_OrAX_IMMz, CMP);

namespace {

template <typename T, typename U, typename V>
ALWAYS_INLINE void SetFlagsMul(State &state, T lhs, T rhs, U res, V res_trunc) {
  const auto new_of = Overflow<tag_mul>::Flag(lhs, rhs, res);

  state.aflag.cf = new_of;
  state.aflag.pf = __mcsema_undefined_bool();
  state.aflag.af = __mcsema_undefined_bool();
  state.aflag.zf = __mcsema_undefined_bool();
  state.aflag.sf = std::is_signed<T>::value ?
      SignFlag(res_trunc) :
      __mcsema_undefined_bool();
  state.aflag.of = new_of;
}

// Creates signed or unsigned multipliers. The `Converter` template template
// parameter is used to take on integer type and convert it to its signed
// counterpart.
template <template <typename> class Converter, size_t size=0>
struct DivMul {

  // 2-operand and 3-operand multipliers truncate their results down to their
  // base types.
  template <typename D, typename S1, typename S2>
  DEF_SEM(MUL, D dst, const S1 src1_, const S2 src2_) {
    typedef typename BaseType<S1>::Type T;
    typedef typename Converter<T>::Type CT;
    typedef typename NextLargerIntegerType<CT>::Type CWT;

    const auto src1 = static_cast<CT>(R(src1_));
    const auto src2 = static_cast<CT>(R(src2_));

    const auto src1_wide = static_cast<CWT>(src1);
    const auto src2_wide = static_cast<CWT>(src2);
    const auto res = static_cast<CWT>(src1_wide * src2_wide);
    const auto res_trunc = static_cast<CT>(res);

    W(dst) = static_cast<T>(res_trunc);
    __mcsema_barrier_compiler();
    SetFlagsMul(state, src1, src2, res, res_trunc);
  }

  // Unsigned multiply without affecting flags.
  template <typename D, typename S>
  DEF_SEM(MULX, D dst1, D dst2, const S src2_) {
    typedef typename BaseType<S>::Type T;
    typedef typename NextLargerIntegerType<T>::Type WT;
    enum {
      kShiftSize = sizeof(T) * 8
    };

    const auto src2 = static_cast<WT>(R(src2_));
    const auto src1 = static_cast<WT>(R(state.gpr.rdx));
    const auto res = src1 * src2;
    W(dst1) = static_cast<T>(res >> kShiftSize);
    W(dst2) = static_cast<T>(res);
  }

  // `MUL8` and `IMUL8` of `AL` doesn't update `RDX`.
  template <typename S2>
  DEF_SEM(MULA_8, const S2 val) {
    typedef typename BaseType<S2>::Type T;  // 8 bit.
    typedef typename NextLargerIntegerType<T>::Type WT;  // 16-bit.
    typedef typename Converter<T>::Type CT;
    typedef typename Converter<WT>::Type CWT;

    const auto src1 = static_cast<CT>(R(state.gpr.rax.byte.low));
    const auto src2 = static_cast<CT>(R(val));

    const auto src1_wide = static_cast<CWT>(src1);
    const auto src2_wide = static_cast<CWT>(src2);
    const auto res = static_cast<CWT>(src1_wide * src2_wide);
    const auto res_trunc = static_cast<CT>(res);

    W(state.gpr.rax.word) = static_cast<WT>(res);
    __mcsema_barrier_compiler();
    SetFlagsMul(state, src1, src2, res, res_trunc);
  }


#define MAKE_MULTIPLIER(size, read_sel, write_sel) \
  template <typename S2> \
  DEF_SEM(MULAD_ ## size, const S2 src2_) { \
    typedef typename BaseType<S2>::Type T; \
    typedef typename NextLargerIntegerType<T>::Type WT; \
    typedef typename Converter<T>::Type CT; \
    typedef typename NextLargerIntegerType<CT>::Type CWT; \
    \
    const auto src1 = static_cast<CT>(R(state.gpr.rax.read_sel)); \
    const auto src2 = static_cast<CT>(R(src2_)); \
    const auto src1_wide = static_cast<CWT>(src1); \
    const auto src2_wide = static_cast<CWT>(src2); \
    const auto res = static_cast<CWT>(src1_wide * src2_wide); \
    const auto res_trunc = static_cast<CT>(res); \
    \
    W(state.gpr.rax.write_sel) = static_cast<T>(res_trunc); \
    W(state.gpr.rdx.write_sel) = static_cast<T>(static_cast<WT>(res) >> size); \
    __mcsema_barrier_compiler(); \
    SetFlagsMul(state, src1, src2, res, res_trunc); \
  }

MAKE_MULTIPLIER(16, word, word)
MAKE_MULTIPLIER(32, dword, IF_64BIT_ELSE(qword, dword))
IF_64BIT(MAKE_MULTIPLIER(64, qword, qword))

#undef MAKE_MULTIPLIER

  // `DIV8` and `IDIV8` of `AL` doesn't update `RDX`.
  template <typename S2>
  DEF_SEM(DIVA_8, const S2 src2_) {

    typedef typename BaseType<S2>::Type T;
    typedef typename NextLargerIntegerType<T>::Type WT;

    typedef typename Converter<T>::Type CT;
    typedef typename NextLargerIntegerType<CT>::Type CWT;

    const auto src1 = static_cast<CWT>(R(state.gpr.rax.word));
    const CWT src2 = static_cast<CT>(R(src2_));

    if (DETECT_RUNTIME_ERRORS && !src2) {
      __mcsema_error(state);
      __builtin_unreachable();
    }

    const CWT quot = src1 / src2;
    const CWT rem = src1 % src2;
    const auto high_half = quot >> 8;

    if (DETECT_RUNTIME_ERRORS &&
        quot &&
        !(!high_half || (std::is_signed<CT>::value && !~high_half))) {
      __mcsema_error(state);
      __builtin_unreachable();
    } else {
      W(state.gpr.rax.byte.low) = static_cast<T>(quot);
      W(state.gpr.rax.byte.high) = static_cast<T>(rem);
      CLEAR_AFLAGS();
    }
  }

#define MAKE_DIVIDER(size, read_sel, write_sel) \
    template <typename S2> \
    DEF_SEM(DIVA_ ## size, const S2 src2_) { \
      typedef typename BaseType<S2>::Type T; \
      typedef typename NextLargerIntegerType<T>::Type WT; \
      \
      typedef typename Converter<T>::Type CT; \
      typedef typename Converter<WT>::Type CWT; \
      \
      const auto src1_low = static_cast<WT>(R(state.gpr.rax.read_sel)); \
      const auto src1_high = static_cast<WT>(R(state.gpr.rdx.read_sel)); \
      \
      const CWT src1 = static_cast<CWT>((src1_high << size) | src1_low);\
      const CWT src2 = static_cast<CT>(R(src2_)); \
      \
      if (DETECT_RUNTIME_ERRORS && !src2) { \
        __mcsema_error(state); \
        __builtin_unreachable(); \
      } \
      \
      const CWT quot = src1 / src2; \
      const CWT rem = src1 % src2; \
      \
      const auto high_half = quot >> size; \
      if (DETECT_RUNTIME_ERRORS && quot && \
          !(!high_half || (std::is_signed<CT>::value && !~high_half))) { \
        __mcsema_error(state); \
        __builtin_unreachable(); \
      } else { \
        W(state.gpr.rax.write_sel) = static_cast<T>(quot); \
        W(state.gpr.rdx.write_sel) = static_cast<T>(rem); \
        CLEAR_AFLAGS(); \
      } \
    }

MAKE_DIVIDER(16, word, word)
MAKE_DIVIDER(32, dword, IF_64BIT_ELSE(qword, dword))
IF_64BIT( MAKE_DIVIDER(64, qword, qword) )

#undef MAKE_DIVIDER
};

template <typename D, typename S1, typename S2>
DEF_SEM(MUL_VFP64, D dst, const S1 src1_, const S2 src2_) {
  typedef typename BaseType<S1>::Type T;  // `D` might be wider than `S1`.
  const T src1 = R(src1_);
  const T src2 = R(src2_);
  W(dst) = src1.doubles * src2.doubles;
}

template <typename D, typename S1, typename S2>
DEF_SEM(MUL_VFP32, D dst, const S1 src1_, const S2 src2_) {
  typedef typename BaseType<S1>::Type T;  // `D` might be wider than `S1`.
  const T src1 = R(src1_);
  const T src2 = R(src2_);
  W(dst) = src1.floats * src2.floats;
}

template <typename D, typename S1, typename S2>
DEF_SEM(DIV_VFP64, D dst, const S1 src1_, const S2 src2_) {
  typedef typename BaseType<S1>::Type T;  // `D` might be wider than `S1`.
  const T src1 = R(src1_);
  const T src2 = R(src2_);
  W(dst) = src1.doubles / src2.doubles;
}

template <typename D, typename S1, typename S2>
DEF_SEM(DIV_VFP32, D dst, const S1 src1_, const S2 src2_) {
  typedef typename BaseType<S1>::Type T;  // `D` might be wider than `S1`.
  const T src1 = R(src1_);
  const T src2 = R(src2_);
  W(dst) = src1.floats / src2.floats;
}

}  // namespace

DEF_ISEL(IMUL_MEMb) = DivMul<SignedIntegerType>::MULA_8<M8>;
DEF_ISEL(IMUL_GPR8) = DivMul<SignedIntegerType>::MULA_8<R8>;
DEF_ISEL(IMUL_MEMv_8) = DivMul<SignedIntegerType>::MULA_8<M8>;
DEF_ISEL(IMUL_MEMv_16) = DivMul<SignedIntegerType>::MULAD_16<M16>;
DEF_ISEL(IMUL_MEMv_32) = DivMul<SignedIntegerType>::MULAD_32<M32>;
IF_64BIT(DEF_ISEL(IMUL_MEMv_64) = DivMul<SignedIntegerType>::MULAD_64<M64>;)
DEF_ISEL(IMUL_GPRv_8) = DivMul<SignedIntegerType>::MULA_8<R8>;
DEF_ISEL(IMUL_GPRv_16) = DivMul<SignedIntegerType>::MULAD_16<R16>;
DEF_ISEL(IMUL_GPRv_32) = DivMul<SignedIntegerType>::MULAD_32<R32>;
IF_64BIT(DEF_ISEL(IMUL_GPRv_64) = DivMul<SignedIntegerType>::MULAD_64<R64>;)

// All dests are registers, albeit different ones from the sources.
DEF_ISEL_RnW_Mn_In(IMUL_GPRv_MEMv_IMMz, DivMul<SignedIntegerType>::MUL);
DEF_ISEL_RnW_Rn_In(IMUL_GPRv_GPRv_IMMz, DivMul<SignedIntegerType>::MUL);
DEF_ISEL_RnW_Mn_In(IMUL_GPRv_MEMv_IMMb, DivMul<SignedIntegerType>::MUL);
DEF_ISEL_RnW_Rn_In(IMUL_GPRv_GPRv_IMMb, DivMul<SignedIntegerType>::MUL);

// Two-operand, but dest is a register so turns into a three-operand.
DEF_ISEL_RnW_Rn_Mn(IMUL_GPRv_MEMv, DivMul<SignedIntegerType>::MUL);
DEF_ISEL_RnW_Rn_Rn(IMUL_GPRv_GPRv, DivMul<SignedIntegerType>::MUL);

DEF_ISEL(MUL_GPR8) = DivMul<UnsignedIntegerType>::MULA_8<R8>;
DEF_ISEL(MUL_MEMb) = DivMul<UnsignedIntegerType>::MULA_8<M8>;
DEF_ISEL(MUL_MEMv_8) = DivMul<UnsignedIntegerType>::MULA_8<M8>;
DEF_ISEL(MUL_MEMv_16) = DivMul<UnsignedIntegerType>::MULAD_16<M16>;
DEF_ISEL(MUL_MEMv_32) = DivMul<UnsignedIntegerType>::MULAD_32<M32>;
IF_64BIT(DEF_ISEL(MUL_MEMv_64) = DivMul<UnsignedIntegerType>::MULAD_64<M64>;)
DEF_ISEL(MUL_GPRv_8) = DivMul<UnsignedIntegerType>::MULA_8<R8>;
DEF_ISEL(MUL_GPRv_16) = DivMul<UnsignedIntegerType>::MULAD_16<R16>;
DEF_ISEL(MUL_GPRv_32) = DivMul<UnsignedIntegerType>::MULAD_32<R32>;
IF_64BIT(DEF_ISEL(MUL_GPRv_64) = DivMul<UnsignedIntegerType>::MULAD_64<R64>;)

DEF_ISEL(MULX_VGPR32d_VGPR32d_VGPR32d) =
    DivMul<UnsignedIntegerType>::MULX<R32W, R32>;
DEF_ISEL(MULX_VGPR32d_VGPR32d_MEMd) =
    DivMul<UnsignedIntegerType>::MULX<R32W, M32>;
IF_64BIT(DEF_ISEL(MULX_VGPR64q_VGPR64q_VGPR64q) =
    DivMul<UnsignedIntegerType>::MULX<R64W, R64>;)
IF_64BIT(DEF_ISEL(MULX_VGPR64q_VGPR64q_MEMq) =
    DivMul<UnsignedIntegerType>::MULX<R64W, M64>;)

DEF_ISEL(MULPS_XMMps_MEMps) = MUL_VFP32<V128W, V128, MV128>;
DEF_ISEL(MULPS_XMMps_XMMps) = MUL_VFP32<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VMULPS_XMMdq_XMMdq_MEMdq) = MUL_VFP32<VV128W, VV128, MV128>;)
IF_AVX(DEF_ISEL(VMULPS_XMMdq_XMMdq_XMMdq) = MUL_VFP32<VV128W, VV128, VV128>;)
IF_AVX(DEF_ISEL(VMULPS_YMMqq_YMMqq_MEMqq) = MUL_VFP32<VV256W, VV256, MV256>;)
IF_AVX(DEF_ISEL(VMULPS_YMMqq_YMMqq_YMMqq) = MUL_VFP32<VV256W, VV256, VV256>;)

DEF_ISEL(MULPD_XMMpd_MEMpd) = MUL_VFP64<V128W, V128, MV128>;
DEF_ISEL(MULPD_XMMpd_XMMpd) = MUL_VFP64<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VMULPD_XMMdq_XMMdq_MEMdq) = MUL_VFP64<VV128W, VV128, MV128>;)
IF_AVX(DEF_ISEL(VMULPD_XMMdq_XMMdq_XMMdq) = MUL_VFP64<VV128W, VV128, VV128>;)
IF_AVX(DEF_ISEL(VMULPD_YMMqq_YMMqq_MEMqq) = MUL_VFP64<VV256W, VV256, MV256>;)
IF_AVX(DEF_ISEL(VMULPD_YMMqq_YMMqq_YMMqq) = MUL_VFP64<VV256W, VV256, VV256>;)

DEF_ISEL(IDIV_MEMb) = DivMul<SignedIntegerType>::DIVA_8<M8>;
DEF_ISEL(IDIV_GPR8) = DivMul<SignedIntegerType>::DIVA_8<R8>;
DEF_ISEL(IDIV_MEMv_8) = DivMul<SignedIntegerType>::DIVA_8<M8>;
DEF_ISEL(IDIV_MEMv_16) = DivMul<SignedIntegerType>::DIVA_16<M16>;
DEF_ISEL(IDIV_MEMv_32) = DivMul<SignedIntegerType>::DIVA_32<M32>;
IF_64BIT(DEF_ISEL(IDIV_MEMv_64) = DivMul<SignedIntegerType>::DIVA_64<M64>;)
DEF_ISEL(IDIV_GPRv_8) = DivMul<SignedIntegerType>::DIVA_8<R8>;
DEF_ISEL(IDIV_GPRv_16) = DivMul<SignedIntegerType>::DIVA_16<R16>;
DEF_ISEL(IDIV_GPRv_32) = DivMul<SignedIntegerType>::DIVA_32<R32>;
IF_64BIT(DEF_ISEL(IDIV_GPRv_64) = DivMul<SignedIntegerType>::DIVA_64<R64>;)

DEF_ISEL(DIV_MEMb) = DivMul<UnsignedIntegerType>::DIVA_8<M8>;
DEF_ISEL(DIV_GPR8) = DivMul<UnsignedIntegerType>::DIVA_8<R8>;
DEF_ISEL(DIV_MEMv_8) = DivMul<UnsignedIntegerType>::DIVA_8<M8>;
DEF_ISEL(DIV_MEMv_16) = DivMul<UnsignedIntegerType>::DIVA_16<M16>;
DEF_ISEL(DIV_MEMv_32) = DivMul<UnsignedIntegerType>::DIVA_32<M32>;
IF_64BIT(DEF_ISEL(DIV_MEMv_64) = DivMul<UnsignedIntegerType>::DIVA_64<M64>;)
DEF_ISEL(DIV_GPRv_8) = DivMul<UnsignedIntegerType>::DIVA_8<R8>;
DEF_ISEL(DIV_GPRv_16) = DivMul<UnsignedIntegerType>::DIVA_16<R16>;
DEF_ISEL(DIV_GPRv_32) = DivMul<UnsignedIntegerType>::DIVA_32<R32>;
IF_64BIT(DEF_ISEL(DIV_GPRv_64) = DivMul<UnsignedIntegerType>::DIVA_64<R64>;)

DEF_ISEL(DIVPS_XMMps_MEMps) = DIV_VFP32<V128W, V128, MV128>;
DEF_ISEL(DIVPS_XMMps_XMMps) = DIV_VFP32<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VDIVPS_XMMdq_XMMdq_MEMdq) = DIV_VFP32<VV128W, VV128, MV128>;)
IF_AVX(DEF_ISEL(VDIVPS_XMMdq_XMMdq_XMMdq) = DIV_VFP32<VV128W, VV128, VV128>;)
IF_AVX(DEF_ISEL(VDIVPS_YMMqq_YMMqq_MEMqq) = DIV_VFP32<VV256W, VV256, MV256>;)
IF_AVX(DEF_ISEL(VDIVPS_YMMqq_YMMqq_YMMqq) = DIV_VFP32<VV256W, VV256, VV256>;)

DEF_ISEL(DIVPD_XMMpd_MEMpd) = DIV_VFP64<V128W, V128, MV128>;
DEF_ISEL(DIVPD_XMMpd_XMMpd) = DIV_VFP64<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VDIVPD_XMMdq_XMMdq_MEMdq) = DIV_VFP64<VV128W, VV128, MV128>;)
IF_AVX(DEF_ISEL(VDIVPD_XMMdq_XMMdq_XMMdq) = DIV_VFP64<VV128W, VV128, VV128>;)
IF_AVX(DEF_ISEL(VDIVPD_YMMqq_YMMqq_MEMqq) = DIV_VFP64<VV256W, VV256, MV256>;)
IF_AVX(DEF_ISEL(VDIVPD_YMMqq_YMMqq_YMMqq) = DIV_VFP64<VV256W, VV256, VV256>;)

namespace {

template <typename D, typename S>
DEF_SEM(INC, D dst, const S src) {
  typedef typename BaseType<S>::Type T;
  const T val1 = R(src);
  const T val2 = 1;
  const T res = val1 + val2;
  W(dst) = res;
  __mcsema_barrier_compiler();
  SetFlagsIncDec<tag_add>(state, val1, val2, res);
}

template <typename D, typename S>
DEF_SEM(DEC, D dst, const S src) {
  typedef typename BaseType<S>::Type T;
  const T val1 = R(src);
  const T val2 = 1;
  const T res = val1 - val2;
  W(dst) = res;
  __mcsema_barrier_compiler();
  SetFlagsIncDec<tag_sub>(state, val1, val2, res);
}

template <typename D, typename S>
DEF_SEM(NEG, D dst, const S src) {
  typedef typename BaseType<S>::Type T;
  typedef typename SignedIntegerType<T>::Type ST;
  const auto val = R(src);
  const auto res = static_cast<T>(-static_cast<ST>(val));
  W(dst) = res;
  __mcsema_barrier_compiler();
  state.aflag.cf = NotZeroFlag(val);
  SetFlagsIncDec<tag_sub, T>(state, 0, val, res);
}

}  // namespace

DEF_ISEL(INC_MEMb) = INC<M8W, M8>;
DEF_ISEL(INC_GPR8) = INC<R8W, R8>;
DEF_ISEL_MnW_Mn(INC_MEMv, INC);
DEF_ISEL_RnW_Rn(INC_GPRv_FFr0, INC);
DEF_ISEL_RnW_Rn(INC_GPRv_40, INC);

DEF_ISEL(DEC_MEMb) = DEC<M8W, M8>;
DEF_ISEL(DEC_GPR8) = DEC<R8W, R8>;
DEF_ISEL_MnW_Mn(DEC_MEMv, DEC);
DEF_ISEL_RnW_Rn(DEC_GPRv_FFr1, DEC);
DEF_ISEL_RnW_Rn(DEC_GPRv_48, DEC);

DEF_ISEL(NEG_MEMb) = NEG<M8W, M8>;
DEF_ISEL(NEG_GPR8) = NEG<R8W, R8>;
DEF_ISEL_MnW_Mn(NEG_MEMv, NEG);
DEF_ISEL_RnW_Rn(NEG_GPRv, NEG);

namespace {

template <typename TagT, typename T>
NEVER_INLINE static bool CarryFlag(T a, T b, T ab, T c, T abc) {
  static_assert(std::is_unsigned<T>::value,
                "Invalid specialization of `CarryFlag` for addition.");
  __mcsema_defer_inlining();
  return Carry<TagT>::Flag(a, b, ab) || Carry<TagT>::Flag(ab, c, abc);
}

template <typename D, typename S1, typename S2>
DEF_SEM(ADC, D dst, const S1 src1_, const S2 src2_) {
  typedef typename BaseType<S1>::Type T;  // `D` might be wider than `S1`.
  const auto src1 = R(src1_);
  const auto src2 = R(src2_);
  const auto carry = static_cast<T>(state.aflag.cf);
  const T res_add = src1 + src2;
  const T res = res_add + carry;
  W(dst) = res;
  __mcsema_barrier_compiler();
  state.aflag.cf = CarryFlag<tag_add>(src1, src2, res_add, carry, res);
  SetFlagsIncDec<tag_add>(state, src1, src2, res);
}

template <typename D, typename S1, typename S2>
DEF_SEM(SBB, D dst, const S1 src1_, const S2 src2_) {
  typedef typename BaseType<S1>::Type T;  // `D` might be wider than `S1`.
  const T src1 = R(src1_);
  const T src2 = R(src2_);
  const T borrow = static_cast<T>(state.aflag.cf);
  const T res_sub = src1 - src2;
  const T res = res_sub - borrow;
  W(dst) = res;
  __mcsema_barrier_compiler();
  state.aflag.cf = CarryFlag<tag_sub>(src1, src2, res_sub, borrow, res);
  SetFlagsIncDec<tag_sub>(state, src1, src2, res);
}

}  // namespace

DEF_ISEL(SBB_MEMb_IMMb_80r3) = SBB<M8W, M8, I8>;
DEF_ISEL(SBB_GPR8_IMMb_80r3) = SBB<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(SBB_MEMv_IMMz, SBB);
DEF_ISEL_RnW_Rn_In(SBB_GPRv_IMMz, SBB);
DEF_ISEL(SBB_MEMb_IMMb_82r3) = SBB<M8W, M8, I8>;
DEF_ISEL(SBB_GPR8_IMMb_82r3) = SBB<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(SBB_MEMv_IMMb, SBB);
DEF_ISEL_RnW_Rn_In(SBB_GPRv_IMMb, SBB);
DEF_ISEL(SBB_MEMb_GPR8) = SBB<M8W, M8, I8>;
DEF_ISEL(SBB_GPR8_GPR8_18) = SBB<R8W, R8, R8>;
DEF_ISEL_MnW_Mn_Rn(SBB_MEMv_GPRv, SBB);
DEF_ISEL_RnW_Rn_Rn(SBB_GPRv_GPRv_19, SBB);
DEF_ISEL(SBB_GPR8_GPR8_1A) = SBB<R8W, R8, R8>;
DEF_ISEL(SBB_GPR8_MEMb) = SBB<R8W, R8, M8>;
DEF_ISEL_RnW_Rn_Rn(SBB_GPRv_GPRv_1B, SBB);
DEF_ISEL_RnW_Rn_Mn(SBB_GPRv_MEMv, SBB);
DEF_ISEL(SBB_AL_IMMb) = SBB<R8W, R8, I8>;
DEF_ISEL_RnW_Rn_In(SBB_OrAX_IMMz, SBB);

DEF_ISEL(ADC_MEMb_IMMb_80r2) = ADC<M8W, M8, I8>;
DEF_ISEL(ADC_GPR8_IMMb_80r2) = ADC<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(ADC_MEMv_IMMz, ADC);
DEF_ISEL_RnW_Rn_In(ADC_GPRv_IMMz, ADC);
DEF_ISEL(ADC_MEMb_IMMb_82r2) = ADC<M8W, M8, I8>;
DEF_ISEL(ADC_GPR8_IMMb_82r2) = ADC<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(ADC_MEMv_IMMb, ADC);
DEF_ISEL_RnW_Rn_In(ADC_GPRv_IMMb, ADC);
DEF_ISEL(ADC_MEMb_GPR8) = ADC<M8W, M8, R8>;
DEF_ISEL(ADC_GPR8_GPR8_10) = ADC<R8W, R8, R8>;
DEF_ISEL_MnW_Mn_Rn(ADC_MEMv_GPRv, ADC);
DEF_ISEL_RnW_Rn_Rn(ADC_GPRv_GPRv_11, ADC);
DEF_ISEL(ADC_GPR8_MEMb) = ADC<R8W, R8, M8>;
DEF_ISEL(ADC_GPR8_GPR8_12) = ADC<R8W, R8, R8>;
DEF_ISEL_RnW_Rn_Mn(ADC_GPRv_MEMv, ADC);
DEF_ISEL_RnW_Rn_Rn(ADC_GPRv_GPRv_13, ADC);
DEF_ISEL(ADC_AL_IMMb) = ADC<R8W, R8, I8>;
DEF_ISEL_RnW_Rn_In(ADC_OrAX_IMMz, ADC);

namespace {

template <template <typename> class Converter>
struct ShiftRight {
  template <typename D, typename S1, typename S2>
  DEF_SEM(DO, D dst, S1 src1_, S2 src2_) {
    typedef typename BaseType<S1>::Type UT;
    typedef typename Converter<UT>::Type T;
    enum : T {
      // The mask is based on the REX.W prefix being used and 64-bit mode. We
      // determine this based on the source being a 64-bit operand.
      //
      // Note: The mask will be 31 even for 16- and 8-bit operands.
      kArchMask = static_cast<T>(8 == sizeof(T) ? 0x3FU : 0x1FU),
      kNumBits = sizeof(T) * 8
    };

    const UT shift = R(src2_) & kArchMask;
    if (0 == shift) {
      return;  // No flags affected.
    }

    const auto val = static_cast<T>(R(src1_));
    T new_val = 0;
    auto new_of = false;
    auto new_cf = false;

    if (1 == shift) {
      if (std::is_signed<T>::value) {
        new_of = false;
      } else {
        new_of = SignFlag(val);
      }
      new_cf = val & 1;
      new_val = val >> 1;

    } else if (shift < kNumBits) {
      const T res = val >> (shift - 1);

      new_of = __mcsema_undefined_bool();
      new_cf = res & 1;
      new_val = res >> 1;

    } else {
      new_of = __mcsema_undefined_bool();
      new_cf = __mcsema_undefined_bool();
      if (std::is_signed<T>::value) {
        if (SignFlag(val)) {
          new_val = static_cast<T>(std::numeric_limits<UT>::max());
        } else {
          new_val = 0;
        }
      } else {
        new_val = 0;
      }
    }

    W(dst) = static_cast<UT>(new_val);

    __mcsema_barrier_compiler();

    state.aflag.cf = new_cf;
    state.aflag.pf = ParityFlag(new_val);
    state.aflag.af = __mcsema_undefined_bool();
    state.aflag.zf = ZeroFlag(new_val);
    state.aflag.sf = std::is_signed<T>::value ? SignFlag(new_val) : false;
    state.aflag.of = new_of;
  }
};

template <typename D, typename S1, typename S2>
DEF_SEM(SHL, D dst, S1 src1_, S2 src2_) {
  typedef typename BaseType<S1>::Type T;
  enum : T {
    // The mask is based on the REX.W prefix being used and 64-bit mode. We
    // determine this based on the source being a 64-bit operand.
    //
    // Note: The mask will be 31 even for 16- and 8-bit operands.
    kArchMask = static_cast<T>(8 == sizeof(T) ? 0x3FU : 0x1FU),
    kNumBits = sizeof(T) * 8
  };

  const T shift = R(src2_) & kArchMask;
  if (0 == shift) {
    return;  // No flags affected.
  }

  const auto val = R(src1_);
  T new_val = 0;
  auto new_cf = false;
  auto new_of = false;

  if (1 == shift) {
    const T res = val << 1;
    const auto msb = SignFlag(val);
    const auto new_msb = SignFlag(res);

    new_of = msb != new_msb;
    new_cf = msb;
    new_val = res;

  } else if (shift < kNumBits) {
    const T res = val << (shift - 1);
    const auto msb = SignFlag(res);

    new_of = __mcsema_undefined_bool();
    new_cf = msb;
    new_val = res << 1;

  } else {
    new_of = __mcsema_undefined_bool();
    new_cf = __mcsema_undefined_bool();
    new_val = 0;
  }

  W(dst) = new_val;

  __mcsema_barrier_compiler();

  state.aflag.cf = new_cf;
  state.aflag.pf = ParityFlag(new_val);
  state.aflag.af = __mcsema_undefined_bool();
  state.aflag.zf = ZeroFlag(new_val);
  state.aflag.sf = SignFlag(new_val);
  state.aflag.of = new_of;
}

}  // namespace

DEF_ISEL(SHR_MEMb_IMMb) = ShiftRight<UnsignedIntegerType>::DO<M8W, M8, I8>;
DEF_ISEL(SHR_GPR8_IMMb) = ShiftRight<UnsignedIntegerType>::DO<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(SHR_MEMv_IMMb, ShiftRight<UnsignedIntegerType>::DO);
DEF_ISEL_RnW_Rn_In(SHR_GPRv_IMMb, ShiftRight<UnsignedIntegerType>::DO);
DEF_ISEL(SHR_MEMb_ONE) = ShiftRight<UnsignedIntegerType>::DO<M8W, M8, I8>;
DEF_ISEL(SHR_GPR8_ONE) = ShiftRight<UnsignedIntegerType>::DO<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(SHR_MEMv_ONE, ShiftRight<UnsignedIntegerType>::DO);
DEF_ISEL_RnW_Rn_In(SHR_GPRv_ONE, ShiftRight<UnsignedIntegerType>::DO);
DEF_ISEL(SHR_MEMb_CL) = ShiftRight<UnsignedIntegerType>::DO<M8W, M8, R8>;
DEF_ISEL(SHR_GPR8_CL) = ShiftRight<UnsignedIntegerType>::DO<R8W, R8, R8>;
DEF_ISEL_MnW_Mn_Rn(SHR_MEMv_CL, ShiftRight<UnsignedIntegerType>::DO);
DEF_ISEL_RnW_Rn_Rn(SHR_GPRv_CL, ShiftRight<UnsignedIntegerType>::DO);

DEF_ISEL(SAR_MEMb_IMMb) = ShiftRight<SignedIntegerType>::DO<M8W, M8, I8>;
DEF_ISEL(SAR_GPR8_IMMb) = ShiftRight<SignedIntegerType>::DO<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(SAR_MEMv_IMMb, ShiftRight<SignedIntegerType>::DO);
DEF_ISEL_RnW_Rn_In(SAR_GPRv_IMMb, ShiftRight<SignedIntegerType>::DO);
DEF_ISEL(SAR_MEMb_ONE) = ShiftRight<SignedIntegerType>::DO<M8W, M8, I8>;
DEF_ISEL(SAR_GPR8_ONE) = ShiftRight<SignedIntegerType>::DO<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(SAR_MEMv_ONE, ShiftRight<SignedIntegerType>::DO);
DEF_ISEL_RnW_Rn_In(SAR_GPRv_ONE, ShiftRight<SignedIntegerType>::DO);
DEF_ISEL(SAR_MEMb_CL) = ShiftRight<SignedIntegerType>::DO<M8W, M8, R8>;
DEF_ISEL(SAR_GPR8_CL) = ShiftRight<SignedIntegerType>::DO<R8W, R8, R8>;
DEF_ISEL_MnW_Mn_Rn(SAR_MEMv_CL, ShiftRight<SignedIntegerType>::DO);
DEF_ISEL_RnW_Rn_Rn(SAR_GPRv_CL, ShiftRight<SignedIntegerType>::DO);

DEF_ISEL(SHL_MEMb_IMMb_C0r4) = SHL<M8W, M8, I8>;
DEF_ISEL(SHL_GPR8_IMMb_C0r4) = SHL<R8W, R8, I8>;
DEF_ISEL(SHL_MEMb_IMMb_C0r6) = SHL<M8W, M8, I8>;
DEF_ISEL(SHL_GPR8_IMMb_C0r6) = SHL<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(SHL_MEMv_IMMb_C1r4, SHL);
DEF_ISEL_RnW_Rn_In(SHL_GPRv_IMMb_C1r4, SHL);
DEF_ISEL_MnW_Mn_In(SHL_MEMv_IMMb_C1r6, SHL);
DEF_ISEL_RnW_Rn_In(SHL_GPRv_IMMb_C1r6, SHL);
DEF_ISEL(SHL_MEMb_ONE_D0r4) = SHL<M8W, M8, I8>;
DEF_ISEL(SHL_GPR8_ONE_D0r4) = SHL<R8W, R8, I8>;
DEF_ISEL(SHL_MEMb_ONE_D0r6) = SHL<M8W, M8, I8>;
DEF_ISEL(SHL_GPR8_ONE_D0r6) = SHL<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(SHL_MEMv_ONE_D1r6, SHL);
DEF_ISEL_RnW_Rn_In(SHL_GPRv_ONE_D1r6, SHL);
DEF_ISEL_MnW_Mn_In(SHL_MEMv_ONE_D1r4, SHL);
DEF_ISEL_RnW_Rn_In(SHL_GPRv_ONE_D1r4, SHL);
DEF_ISEL(SHL_MEMb_CL_D2r4) = SHL<M8W, M8, R8>;
DEF_ISEL(SHL_GPR8_CL_D2r4) = SHL<R8W, R8, R8>;
DEF_ISEL(SHL_MEMb_CL_D2r6) = SHL<M8W, M8, R8>;
DEF_ISEL(SHL_GPR8_CL_D2r6) = SHL<R8W, R8, R8>;
DEF_ISEL_MnW_Mn_Rn(SHL_MEMv_CL_D3r4, SHL);
DEF_ISEL_RnW_Rn_Rn(SHL_GPRv_CL_D3r4, SHL);
DEF_ISEL_MnW_Mn_Rn(SHL_MEMv_CL_D3r6, SHL);
DEF_ISEL_RnW_Rn_Rn(SHL_GPRv_CL_D3r6, SHL);

#endif  // MCSEMA_ARCH_X86_SEMANTICS_BINARY_H_
