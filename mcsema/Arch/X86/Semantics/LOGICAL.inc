/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(AND, D dst, S1 src1_, S2 src2_) {
  typedef typename BaseType<S1>::Type T;
  const T src1 = R(src1_);
  const T src2 = R(src2_);
  const T res = src1 & src2;
  SET_AFLAGS_SZAP(src1, src2, res);
  W(dst) = res;
}

template <typename D, typename S1, typename S2>
DEF_SEM(OR, D dst, S1 src1_, S2 src2_) {
  typedef typename BaseType<S1>::Type T;
  const T src1 = R(src1_);
  const T src2 = R(src2_);
  const T res = src1 | src2;
  SET_AFLAGS_SZAP(src1, src2, res);
  W(dst) = res;
}

template <typename D, typename S1, typename S2>
DEF_SEM(XOR, D dst, S1 src1_, S2 src2_) {
  typedef typename BaseType<S1>::Type T;
  const T src1 = R(src1_);
  const T src2 = R(src2_);
  const T res = src1 ^ src2;
  SET_AFLAGS_SZAP(src1, src2, res);
  W(dst) = res;
}

template <typename D, typename S1>
DEF_SEM(NOT, D dst_src1, S1 src1_) {
  W(dst_src1) = ~R(src1_);
}

template <typename S1, typename S2>
DEF_SEM(TEST, S1 src1_, S2 src2_) {
  typedef typename BaseType<S1>::Type T;
  const T src1 = R(src1_);
  const T src2 = R(src2_);
  const T res = src1 & src2;
  SET_AFLAGS_SZAP(src1, src2, res);
}

}  // namespace

DEF_ISEL(AND_MEMb_IMMb_80r4_8) = AND<M8W, M8, I8>;
DEF_ISEL(AND_GPR8_IMMb_80r4_8) = AND<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(AND_MEMv_IMMz, AND);
DEF_ISEL_RnW_Rn_In(AND_GPRv_IMMz, AND);
DEF_ISEL(AND_MEMb_IMMb_82r4_8) = AND<M8W, M8, I8>;
DEF_ISEL(AND_GPR8_IMMb_82r4_8) = AND<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(AND_MEMv_IMMb, AND);
DEF_ISEL_RnW_Rn_In(AND_GPRv_IMMb, AND);
DEF_ISEL(AND_MEMb_GPR8_8) = AND<M8W, M8, R8>;
DEF_ISEL(AND_GPR8_GPR8_20_8) = AND<R8W, R8, R8>;
DEF_ISEL_MnW_Mn_Rn(AND_MEMv_GPRv, AND);
DEF_ISEL_RnW_Rn_Rn(AND_GPRv_GPRv_21, AND);
DEF_ISEL(AND_GPR8_GPR8_22_8) = AND<R8W, R8, R8>;
DEF_ISEL(AND_GPR8_MEMb_8) = AND<R8W, R8, M8>;
DEF_ISEL_RnW_Rn_Rn(AND_GPRv_GPRv_23, AND);
DEF_ISEL_RnW_Rn_Mn(AND_GPRv_MEMv, AND);
DEF_ISEL(AND_AL_IMMb_8) = AND<R8W, R8, I8>;
DEF_ISEL_RnW_Rn_In(AND_OrAX_IMMz, AND);

DEF_ISEL(OR_MEMb_IMMb_80r1_8) = OR<M8W, M8, I8>;
DEF_ISEL(OR_GPR8_IMMb_80r1_8) = OR<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(OR_MEMv_IMMz, OR);
DEF_ISEL_RnW_Rn_In(OR_GPRv_IMMz, OR);
DEF_ISEL(OR_MEMb_IMMb_82r1_8) = OR<M8W, M8, I8>;
DEF_ISEL(OR_GPR8_IMMb_82r1_8) = OR<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(OR_MEMv_IMMb, OR);
DEF_ISEL_RnW_Rn_In(OR_GPRv_IMMb, OR);
DEF_ISEL(OR_MEMb_GPR8_8) = OR<M8W, M8, R8>;
DEF_ISEL(OR_GPR8_GPR8_08_8) = OR<R8W, R8, R8>;
DEF_ISEL_MnW_Mn_Rn(OR_MEMv_GPRv, OR);
DEF_ISEL_RnW_Rn_Rn(OR_GPRv_GPRv_09, OR);
DEF_ISEL(OR_GPR8_MEMb_8) = OR<R8W, R8, M8>;
DEF_ISEL(OR_GPR8_GPR8_0A_8) = OR<R8W, R8, R8>;
DEF_ISEL_RnW_Rn_Mn(OR_GPRv_MEMv, OR);
DEF_ISEL_RnW_Rn_Rn(OR_GPRv_GPRv_0B, OR);
DEF_ISEL(OR_AL_IMMb_8) = OR<R8W, R8, I8>;
DEF_ISEL_RnW_Rn_In(OR_OrAX_IMMz, OR);

DEF_ISEL(XOR_MEMb_IMMb_80r6_8) = XOR<M8W, M8, I8>;
DEF_ISEL(XOR_GPR8_IMMb_80r6_8) = XOR<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(XOR_MEMv_IMMz, XOR);
DEF_ISEL_RnW_Rn_In(XOR_GPRv_IMMz, XOR);
DEF_ISEL(XOR_MEMb_IMMb_82r6_8) = XOR<M8W, M8, I8>;
DEF_ISEL(XOR_GPR8_IMMb_82r6_8) = XOR<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(XOR_MEMv_IMMb, XOR);
DEF_ISEL_RnW_Rn_In(XOR_GPRv_IMMb, XOR);
DEF_ISEL(XOR_MEMb_GPR8_8) = XOR<M8W, M8, R8>;
DEF_ISEL(XOR_GPR8_GPR8_30_8) = XOR<R8W, R8, R8>;
DEF_ISEL_MnW_Mn_Rn(XOR_MEMv_GPRv, XOR);
DEF_ISEL_RnW_Rn_Rn(XOR_GPRv_GPRv_31, XOR);
DEF_ISEL(XOR_GPR8_GPR8_32_8) = XOR<R8W, R8, R8>;
DEF_ISEL(XOR_GPR8_MEMb_8) = XOR<R8W, R8, M8>;
DEF_ISEL_RnW_Rn_Rn(XOR_GPRv_GPRv_33, XOR);
DEF_ISEL_RnW_Rn_Mn(XOR_GPRv_MEMv, XOR);
DEF_ISEL(XOR_AL_IMMb_8) = XOR<R8W, R8, I8>;
DEF_ISEL_RnW_Rn_In(XOR_OrAX_IMMz, XOR);

DEF_ISEL(NOT_MEMb_8) = NOT<M8W, M8>;
DEF_ISEL(NOT_GPR8_8) = NOT<R8W, R8>;
DEF_ISEL_MnW_Mn(NOT_MEMv, NOT);
DEF_ISEL_RnW_Rn(NOT_GPRv, NOT);

DEF_ISEL(TEST_MEMb_IMMb_F6r0_8) = TEST<M8, I8>;
DEF_ISEL(TEST_MEMb_IMMb_F6r1_8) = TEST<M8, I8>;
DEF_ISEL(TEST_GPR8_IMMb_F6r0_8) = TEST<R8, I8>;
DEF_ISEL(TEST_GPR8_IMMb_F6r1_8) = TEST<R8, I8>;
DEF_ISEL_Mn_In(TEST_MEMv_IMMz_F7r0, TEST);
DEF_ISEL_Mn_In(TEST_MEMv_IMMz_F7r1, TEST);
DEF_ISEL_Rn_In(TEST_GPRv_IMMz_F7r0, TEST);
DEF_ISEL_Rn_In(TEST_GPRv_IMMz_F7r1, TEST);
DEF_ISEL(TEST_MEMb_GPR8_8) = TEST<M8, R8>;
DEF_ISEL(TEST_GPR8_GPR8_8) = TEST<R8, R8>;
DEF_ISEL_Mn_Rn(TEST_MEMv_GPRv, TEST);
DEF_ISEL_Rn_Rn(TEST_GPRv_GPRv, TEST);
DEF_ISEL(TEST_AL_IMMb_8) = TEST<R8, I8>;
DEF_ISEL_Rn_In(TEST_OrAX_IMMz, TEST);

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(PAND, D dst, S1 src1_, S2 src2_) {
  typedef typename BaseType<S1>::Type T;
  typedef typename BaseType<D>::Type DT;  // Note: sizeof(DT) >= sizeof(T).
  const DT src1 = R(src1_);
  const DT src2 = R(src2_);
  W(dst) = src1.iwords & src2.iwords;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PANDN, D dst, S1 src1_, S2 src2_) {
  typedef typename BaseType<S1>::Type T;
  typedef typename BaseType<D>::Type DT;  // Note: sizeof(DT) >= sizeof(T).
  const DT src1 = R(src1_);
  const DT src2 = R(src2_);
  W(dst) = (~src1.iwords) & src2.iwords;
}
template <typename D, typename S1, typename S2>
DEF_SEM(POR, D dst, S1 src1_, S2 src2_) {
  typedef typename BaseType<S1>::Type T;
  typedef typename BaseType<D>::Type DT;  // Note: sizeof(DT) >= sizeof(T).
  const DT src1 = R(src1_);
  const DT src2 = R(src2_);
  W(dst) = src1.iwords | src2.iwords;
}
template <typename D, typename S1, typename S2>
DEF_SEM(PXOR, D dst, S1 src1_, S2 src2_) {
  typedef typename BaseType<S1>::Type T;
  typedef typename BaseType<D>::Type DT;  // Note: sizeof(DT) >= sizeof(T).
  const DT src1 = R(src1_);
  const DT src2 = R(src2_);
  W(dst) = src1.iwords ^ src2.iwords;
}

/*
template <typename S1, typename S2>
DEF_SEM(PTEST, S1 src1_, S2 src2_) {
  typedef typename BaseType<S1>::Type T;
  const T src1 = R(src1_);
  const T src2 = R(src2_);
  //T res;
  //res.qwords = src1.qwords & src2.qwords;
  (void) src1;
  (void) src2;
}
*/
}  // namespace

DEF_ISEL(PXORq_MEMq_64) = PXOR<V64W, V64, MV64>;
DEF_ISEL(PXORqq_64) = PXOR<V64W, V64, V64>;
DEF_ISEL(PXOR_XMMdq_MEMdq_32) = PXOR<V128W, V128, MV128>;
DEF_ISEL(PXOR_XMMdq_XMMdq_32) = PXOR<V128W, V128, V128>;
DEF_ISEL(VPXOR_XMMdq_XMMdq_MEMdq_128) = PXOR<V128W, V128, MV128>;
DEF_ISEL(VPXOR_XMMdq_XMMdq_XMMdq_128) = PXOR<V128W, V128, MV128>;
IF_AVX( DEF_ISEL(VPXOR_YMMqq_YMMqq_MEMqq_256) = PXOR<V256W, V256, MV256>; )
IF_AVX( DEF_ISEL(VPXOR_YMMqq_YMMqq_YMMqq_256) = PXOR<V256W, V256, MV256>; )

DEF_ISEL(PANDq_MEMq_64) = PAND<V64W, V64, MV64>;
DEF_ISEL(PANDqq_64) = PAND<V64W, V64, V64>;
DEF_ISEL(PAND_XMMdq_MEMdq_32) = PAND<V128W, V128, MV128>;
DEF_ISEL(PAND_XMMdq_XMMdq_32) = PAND<V128W, V128, V128>;
DEF_ISEL(VPAND_XMMdq_XMMdq_MEMdq_128) = PAND<V128W, V128, MV128>;
DEF_ISEL(VPAND_XMMdq_XMMdq_XMMdq_128) = PAND<V128W, V128, MV128>;
IF_AVX( DEF_ISEL(VPAND_YMMqq_YMMqq_MEMqq_256) = PAND<V256W, V256, MV256>; )
IF_AVX( DEF_ISEL(VPAND_YMMqq_YMMqq_YMMqq_256) = PAND<V256W, V256, MV256>; )

DEF_ISEL(PANDNq_MEMq_64) = PANDN<V64W, V64, MV64>;
DEF_ISEL(PANDNqq_64) = PANDN<V64W, V64, V64>;
DEF_ISEL(PANDN_XMMdq_MEMdq_32) = PANDN<V128W, V128, MV128>;
DEF_ISEL(PANDN_XMMdq_XMMdq_32) = PANDN<V128W, V128, V128>;
DEF_ISEL(VPANDN_XMMdq_XMMdq_MEMdq_128) = PANDN<V128W, V128, MV128>;
DEF_ISEL(VPANDN_XMMdq_XMMdq_XMMdq_128) = PANDN<V128W, V128, MV128>;
IF_AVX( DEF_ISEL(VPANDN_YMMqq_YMMqq_MEMqq_256) = PANDN<V256W, V256, MV256>; )
IF_AVX( DEF_ISEL(VPANDN_YMMqq_YMMqq_YMMqq_256) = PANDN<V256W, V256, MV256>; )

DEF_ISEL(PORq_MEMq_64) = POR<V64W, V64, MV64>;
DEF_ISEL(PORqq_64) = POR<V64W, V64, V64>;
DEF_ISEL(POR_XMMdq_MEMdq_32) = POR<V128W, V128, MV128>;
DEF_ISEL(POR_XMMdq_XMMdq_32) = POR<V128W, V128, V128>;
DEF_ISEL(VPOR_XMMdq_XMMdq_MEMdq_128) = POR<V128W, V128, MV128>;
DEF_ISEL(VPOR_XMMdq_XMMdq_XMMdq_128) = POR<V128W, V128, MV128>;
IF_AVX( DEF_ISEL(VPOR_YMMqq_YMMqq_MEMqq_256) = POR<V256W, V256, MV256>; )
IF_AVX( DEF_ISEL(VPOR_YMMqq_YMMqq_YMMqq_256) = POR<V256W, V256, MV256>; )

/*

822 PTEST PTEST_XMMdq_MEMdq LOGICAL SSE4 SSE4 ATTRIBUTES: REQUIRES_ALIGNMENT SIMD_PACKED_ALIGNMENT
823 PTEST PTEST_XMMdq_XMMdq LOGICAL SSE4 SSE4 ATTRIBUTES: REQUIRES_ALIGNMENT SIMD_PACKED_ALIGNMENT

1737 XTEST XTEST LOGICAL RTM RTM ATTRIBUTES:

2246 VPTEST VPTEST_XMMdq_MEMdq LOGICAL AVX AVX ATTRIBUTES:
2247 VPTEST VPTEST_XMMdq_XMMdq LOGICAL AVX AVX ATTRIBUTES:
2248 VPTEST VPTEST_YMMqq_MEMqq LOGICAL AVX AVX ATTRIBUTES:
2249 VPTEST VPTEST_YMMqq_YMMqq LOGICAL AVX AVX ATTRIBUTES:

 */
