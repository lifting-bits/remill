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

#undef DEFINE_OP

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
DEF_ISEL_RnW_Rn(NOT_GRPv, NOT);

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
