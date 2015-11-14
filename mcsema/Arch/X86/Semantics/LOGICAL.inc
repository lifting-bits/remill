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

template <typename Op, typename D, typename S1>
DEF_SEM(NOT_REG, D dst_src1, S1 src1_) {
  W(dst_src1) = ~R(src1_);
}

template <typename Op, typename D>
DEF_SEM(NOT_MEM, D dst_src1) {
  W(dst_src1) = ~R(dst_src1);
}

}  // namespace

