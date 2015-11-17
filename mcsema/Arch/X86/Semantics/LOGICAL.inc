/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

namespace {

template <typename Op, typename D, typename S1>
DEF_SEM(BITWISE_OP, D dst_src1, S1 src2_) {
  auto src1 = R(dst_src1);
  auto src2 = R(src2_);
  auto res = Op()(src1, src2);
  SET_BFLAGS(src1, src2, res);
  W(dst_src1) = res;
}

template <typename Op, typename D, typename S1, typename S2>
DEF_SEM(BITWISE_OP2, D dst, S1 src1_, S2 src2_) {
  auto src1 = R(src1_);
  auto src2 = R(src2_);
  auto res = Op()(src1, src2);
  SET_BFLAGS(src1, src2, res);
  W(dst) = res;
}

#define DEFINE_OP(name, op) \
    template <typename D, typename S1> \
    DEF_SEM(name, D dst_src1, S1 src2_) { \
      BITWISE_OP<op<S1>, D, S1>(state, dst_src1, src2_); \
    } \
    template <typename D, typename S1, typename S2> \
    DEF_SEM(name ## 2, D dst, S1 src1_, S2 src2_) { \
      BITWISE_OP2<op<S1>, D, S1>(state, dst, src1_, src2_); \
    }

DEFINE_OP(AND, std::bit_and)
DEFINE_OP(OR, std::bit_or)
DEFINE_OP(XOR, std::bit_xor)

#undef DEFINE_OP

template <typename D, typename S1>
DEF_SEM(NOT_REG, D dst_src1, S1 src1_) {
  W(dst_src1) = ~R(src1_);
}

template <typename D>
DEF_SEM(NOT_MEM, D dst_src1) {
  W(dst_src1) = ~R(dst_src1);
}

template <typename D, typename S1>
DEF_SEM(TEST, D src1_, S1 src2_) {
  auto src1 = static_cast<intptr_t>(R(src1_));
  auto src2 = static_cast<intptr_t>(R(src2_));
  auto res = src1 & src2;
  SET_BFLAGS(src1, src2, res);
}

}  // namespace

DEF_ISEL(AND_MEMb_IMMb_80r4_8) = AND<M8, I8>;
DEF_ISEL(AND_GPR8_IMMb_80r4_8) = AND2<R8W, R8, I8>;
DEF_ISEL_Mn_Mn_In(AND_MEMv_IMMz, AND);
DEF_ISEL_Rn_Rn_In(AND_GPRv_IMMz, AND2);
DEF_ISEL(AND_MEMb_IMMb_82r4_8) = AND<M8, I8>;
DEF_ISEL(AND_GPR8_IMMb_82r4_8) = AND2<R8W, R8, I8>;
DEF_ISEL_Mn_Mn_In(AND_MEMv_IMMb, AND);
DEF_ISEL_Rn_Rn_In(AND_GPRv_IMMb, AND2);
DEF_ISEL(AND_MEMb_GPR8_8) = AND<M8, R8>;
DEF_ISEL(AND_GPR8_GPR8_20_8) = AND2<R8W, R8, R8>;
DEF_ISEL_Mn_Mn_Rn(AND_MEMv_GPRv, AND);
DEF_ISEL_Rn_Rn_Rn(AND_GPRv_GPRv_21, AND2);
DEF_ISEL(AND_GPR8_GPR8_22_8) = AND2<R8W, R8, R8>;
DEF_ISEL(AND_GPR8_MEMb_8) = AND2<R8W, R8, M8>;
DEF_ISEL_Rn_Rn_Rn(AND_GPRv_GPRv_23, AND2);
DEF_ISEL_Rn_Rn_Mn(AND_GPRv_MEMv, AND2);
DEF_ISEL(AND_AL_IMMb_8) = AND2<R8W, R8, I8>;
DEF_ISEL_Rn_Rn_In(AND_OrAX_IMMz, AND2);

DEF_ISEL(OR_MEMb_IMMb_80r1_8) = OR<M8, I8>;
DEF_ISEL(OR_GPR8_IMMb_80r1_8) = OR2<R8W, R8, I8>;
DEF_ISEL_Mn_Mn_In(OR_MEMv_IMMz, OR);
DEF_ISEL_Rn_Rn_In(OR_GPRv_IMMz, OR2);
DEF_ISEL(OR_MEMb_IMMb_82r1_8) = OR<M8, I8>;
DEF_ISEL(OR_GPR8_IMMb_82r1_8) = OR2<R8W, R8, I8>;
DEF_ISEL_Mn_Mn_In(OR_MEMv_IMMb, OR);
DEF_ISEL_Rn_Rn_In(OR_GPRv_IMMb, OR2);
DEF_ISEL(OR_MEMb_GPR8_8) = OR<M8, R8>;
DEF_ISEL(OR_GPR8_GPR8_08_8) = OR2<R8W, R8, R8>;
DEF_ISEL_Mn_Mn_Rn(OR_MEMv_GPRv, OR);
DEF_ISEL_Rn_Rn_Rn(OR_GPRv_GPRv_09, OR2);
DEF_ISEL(OR_GPR8_MEMb_8) = OR2<R8W, R8, M8>;
DEF_ISEL(OR_GPR8_GPR8_0A_8) = OR2<R8W, R8, R8>;
DEF_ISEL_Rn_Rn_Mn(OR_GPRv_MEMv, OR2);
DEF_ISEL_Rn_Rn_Rn(OR_GPRv_GPRv_0B, OR2);
DEF_ISEL(OR_AL_IMMb_8) = OR2<R8W, R8, I8>;
DEF_ISEL_Rn_Rn_In(OR_OrAX_IMMz, OR2);

DEF_ISEL(XOR_MEMb_IMMb_80r6_8) = XOR<M8, I8>;
DEF_ISEL(XOR_GPR8_IMMb_80r6_8) = XOR2<R8W, R8, I8>;
DEF_ISEL_Mn_Mn_In(XOR_MEMv_IMMz, XOR);
DEF_ISEL_Rn_Rn_In(XOR_GPRv_IMMz, XOR2);
DEF_ISEL(XOR_MEMb_IMMb_82r6_8) = XOR<M8, I8>;
DEF_ISEL(XOR_GPR8_IMMb_82r6_8) = XOR2<R8W, R8, I8>;
DEF_ISEL_Mn_Mn_In(XOR_MEMv_IMMb, XOR);
DEF_ISEL_Rn_Rn_In(XOR_GPRv_IMMb, XOR2);
DEF_ISEL(XOR_MEMb_GPR8_8) = XOR<M8, R8>;
DEF_ISEL(XOR_GPR8_GPR8_30_8) = XOR2<R8W, R8, R8>;
DEF_ISEL_Mn_Mn_Rn(XOR_MEMv_GPRv, XOR);
DEF_ISEL_Rn_Rn_Rn(XOR_GPRv_GPRv_31, XOR2);
DEF_ISEL(XOR_GPR8_GPR8_32_8) = XOR2<R8W, R8, R8>;
DEF_ISEL(XOR_GPR8_MEMb_8) = XOR2<R8W, R8, M8>;
DEF_ISEL_Rn_Rn_Rn(XOR_GPRv_GPRv_33, XOR2);
DEF_ISEL_Rn_Rn_Mn(XOR_GPRv_MEMv, XOR2);
DEF_ISEL(XOR_AL_IMMb_8) = XOR2<R8W, R8, I8>;
DEF_ISEL_Rn_Rn_In(XOR_OrAX_IMMz, XOR2);

DEF_ISEL(NOT_MEMb_8) = NOT_MEM<M8>;
DEF_ISEL(NOT_GPR8_8) = NOT_REG<R8W, R8>;
DEF_ISEL_Mn_Mn(NOT_MEMv, NOT_MEM);
DEF_ISEL_Rn_Rn(NOT_GRPv, NOT_REG);

DEF_ISEL(TEST_MEMb_IMMb_F6r0_8) = TEST<M8, I8>;
DEF_ISEL(TEST_MEMb_IMMb_F6r1_8) = TEST<M8, I8>;
DEF_ISEL(TEST_GPR8_IMMb_F6r0_8) = TEST<R8, I8>;
DEF_ISEL(TEST_GPR8_IMMb_F6r1_8) = TEST<R8, I8>;
DEF_ISEL_READONLY_Mn_In(TEST_MEMv_IMMz_F7r0, TEST);
DEF_ISEL_READONLY_Mn_In(TEST_MEMv_IMMz_F7r1, TEST);
DEF_ISEL_READONLY_Rn_In(TEST_GPRv_IMMz_F7r0, TEST);
DEF_ISEL_READONLY_Rn_In(TEST_GPRv_IMMz_F7r1, TEST);
DEF_ISEL(TEST_MEMb_GPR8_8) = TEST<M8, R8>;
DEF_ISEL(TEST_GPR8_GPR8_8) = TEST<R8, R8>;
DEF_ISEL_READONLY_Mn_Rn(TEST_MEMv_GPRv, TEST);
DEF_ISEL_READONLY_Rn_Rn(TEST_GPRv_GPRv, TEST);
DEF_ISEL(TEST_AL_IMMb_8) = TEST<R8, I8>;
DEF_ISEL_READONLY_Rn_In(TEST_OrAX_IMMz, TEST);
