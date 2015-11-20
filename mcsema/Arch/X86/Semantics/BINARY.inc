/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <functional>

namespace {

template <typename Op, typename D, typename S1>
DEF_SEM(BINARY_ARITH_OP, D dst_src1, S1 src2_) {
  auto src1 = R(dst_src1);
  auto src2 = R(src2_);
  auto res = Op()(src1, src2);
  SET_AFLAGS_OSZAPC(src1, src2, res);
  W(dst_src1) = res;
}

template <typename Op, typename D, typename S1, typename S2>
DEF_SEM(BINARY_ARITH_OP2, D dst, S1 src1_, S2 src2_) {
  auto src1 = R(src1_);
  auto src2 = R(src2_);
  auto res = Op()(src1, src2);
  SET_AFLAGS_OSZAPC(src1, src2, res);
  W(dst) = res;
}

template <typename D, typename S1>
DEF_SEM(CMP, D src1_, S1 src2_) {
  auto src1 = static_cast<intptr_t>(R(src1_));
  auto src2 = static_cast<intptr_t>(R(src2_));
  auto res = src1 - src2;
  SET_AFLAGS_OSZAPC(src1, src2, res);
}

#define DEFINE_OP(name, op) \
    template <typename D, typename S1> \
    DEF_SEM(name, D dst_src1, S1 src2_) { \
      BINARY_ARITH_OP<op<S1>, D, S1>(state, dst_src1, src2_); \
    } \
    template <typename D, typename S1, typename S2> \
    DEF_SEM(name ## 2, D dst, S1 src1_, S2 src2_) { \
      BINARY_ARITH_OP2<op<S1>, D, S1, S2>(state, dst, src1_, src2_); \
    }
DEFINE_OP(ADD, std::plus)
DEFINE_OP(SUB, std::minus)
#undef DEFINE_OP

// Creates signed or unsigned multipliers. The `Converter` template template
// parameter is used to take on integer type and convert it to its signed
// counterpart.
template <template <typename> class Converter>
struct Multiplier {

  // 2-operand and 3-operand multipliers truncate their results down to their
  // base types.
  template <typename D, typename S1, typename S2>
  DEF_SEM(MUL3, D dst, S1 src1_, S2 src2_) {
    typedef typename BaseType<D>::Type T;
    typedef typename Converter<T>::Type ST;
    auto src1 = static_cast<ST>(R(src1_));
    auto src2 = static_cast<ST>(R(src2_));
    auto res = src1 * src2;
    SET_AFLAGS_OSC(src1, src2, res);
    W(dst) = static_cast<T>(res);
  }

  // `MUL8` and `IMUL8` of `AL` doesn't update `RDX`.
  template <typename S1>
  DEF_SEM(MUL1_8, S1 val) {
    typedef typename BaseType<S1>::Type T;
    typedef typename Converter<T>::Type ConvT;

    typedef typename NextLargerIntegerType<T>::Type WideT;
    typedef typename Converter<WideT>::Type ConvWideT;

    auto src1 = static_cast<ConvWideT>(static_cast<ConvT>(
        state.gpr.rax.byte.low));
    auto src2 = static_cast<ConvWideT>(static_cast<ConvT>(R(val)));
    auto res = src1 * src2;
    SET_AFLAGS_OSC(src1, src2, res);
    state.gpr.rax.word = static_cast<WideT>(res);
  }

#define MAKE_MULTIPLIER(size, read_sel, write_sel) \
    template <typename S1> \
    DEF_SEM(MUL1_ ## size, S1 val) { \
      typedef typename BaseType<S1>::Type T; \
      typedef typename Converter<T>::Type ConvT; \
      \
      typedef typename NextLargerIntegerType<T>::Type WideT; \
      typedef typename Converter<WideT>::Type ConvWideT; \
      \
      auto src1 = static_cast<ConvWideT>(static_cast<ConvT>( \
          state.gpr.rax.read_sel)); \
      auto src2 = static_cast<ConvWideT>(static_cast<ConvT>(R(val))); \
      auto res = src1 * src2; \
      SET_AFLAGS_OSC(src1, src2, res); \
      state.gpr.rdx.write_sel = static_cast<T>(res >> size); \
      state.gpr.rax.write_sel = static_cast<T>(res); \
    }

MAKE_MULTIPLIER(16, word, word)
MAKE_MULTIPLIER(32, dword, full)
IF_64BIT(MAKE_MULTIPLIER(64, full, full))

#undef MAKE_MULTIPLIER

  // `MUL8` and `IMUL8` of `AL` doesn't update `RDX`.
  template <typename S1>
  DEF_SEM(DIV1_8, S1 val) {
    CLEAR_AFLAGS();

    typedef typename BaseType<S1>::Type T;
    typedef typename NextLargerIntegerType<T>::Type WideT;
    typedef typename Converter<T>::Type ConvT;
    typedef typename NextLargerIntegerType<T>::Type ConvWideT;

    auto src1 = static_cast<ConvWideT>(state.gpr.rax.word);
    auto src2 = static_cast<ConvWideT>(static_cast<ConvT>(R(val)));
    auto quot = static_cast<ConvT>(src1 / src2);
    auto rem = static_cast<ConvT>(src1 % src2);

    state.gpr.rax.byte.low = static_cast<T>(quot);
    state.gpr.rax.byte.high = static_cast<T>(rem);
  }

#define MAKE_DIVIDER(size, read_sel, write_sel) \
    template <typename S1> \
    DEF_SEM(DIV1_ ## size, S1 val) { \
      CLEAR_AFLAGS(); \
      typedef typename BaseType<S1>::Type T; \
      typedef typename Converter<T>::Type ConvT; \
      \
      typedef typename NextLargerIntegerType<T>::Type WideT; \
      typedef typename Converter<WideT>::Type ConvWideT; \
      \
      auto src1_low = static_cast<WideT>(state.gpr.rax.read_sel); \
      auto src1_high = static_cast<WideT>(state.gpr.rdx.read_sel); \
      auto src1 = static_cast<ConvWideT>((src1_high << size) | src1_low); \
      auto src2 = static_cast<ConvWideT>(static_cast<ConvT>(R(val))); \
      \
      auto quot = static_cast<ConvT>(src1 / src2); \
      auto rem = static_cast<ConvT>(src1 % src2); \
      state.gpr.rax.write_sel = static_cast<T>(quot); \
      state.gpr.rdx.write_sel = static_cast<T>(rem); \
    }

MAKE_DIVIDER(16, word, word)
MAKE_DIVIDER(32, dword, full)
IF_64BIT( MAKE_DIVIDER(64, full, full) )

#undef MAKE_DIVIDER
};

}  // namespace

DEF_ISEL(ADD_MEMb_IMMb_80r0_8) = ADD<M8, I8>;
DEF_ISEL(ADD_GPR8_IMMb_80r0_8) = ADD2<R8W, R8, I8>;
DEF_ISEL_Mn_Mn_In(ADD_MEMv_IMMz, ADD);
DEF_ISEL_Rn_Rn_In(ADD_GPRv_IMMz, ADD2);
DEF_ISEL(ADD_MEMb_IMMb_82r0_8) = ADD<M8, I8>;
DEF_ISEL(ADD_GPR8_IMMb_82r0_8) = ADD2<R8W, R8, I8>;
DEF_ISEL_Mn_Mn_In(ADD_MEMv_IMMb, ADD);
DEF_ISEL_Rn_Rn_In(ADD_GPRv_IMMb, ADD2);
DEF_ISEL(ADD_MEMb_GPR8_8) = ADD<M8, R8>;
DEF_ISEL(ADD_GPR8_GPR8_00_8) = ADD2<R8W, R8, R8>;
DEF_ISEL_Mn_Mn_Rn(ADD_MEMv_GPRv, ADD);
DEF_ISEL_Rn_Rn_Rn(ADD_GPRv_GPRv_01, ADD2);
DEF_ISEL(ADD_GPR8_MEMb_8) = ADD2<R8W, R8, M8>;
DEF_ISEL(ADD_GPR8_GPR8_02_8) = ADD2<R8W, R8, R8>;
DEF_ISEL_Rn_Rn_Mn(ADD_GPRv_MEMv, ADD2);
DEF_ISEL_Rn_Rn_Rn(ADD_GPRv_GPRv_03, ADD2);
DEF_ISEL(ADD_AL_IMMb) = ADD2<R8W, R8, I8>;
DEF_ISEL_Rn_Rn_In(ADD_OrAX_IMMz, ADD2);

DEF_ISEL(SUB_MEMb_IMMb_80r5_8) = SUB<M8, I8>;
DEF_ISEL(SUB_GPR8_IMMb_80r5_8) = SUB2<R8W, R8, I8>;
DEF_ISEL_Mn_Mn_In(SUB_MEMv_IMMz, SUB);
DEF_ISEL_Rn_Rn_In(SUB_GPRv_IMMz, SUB2);
DEF_ISEL(SUB_MEMb_IMMb_82r5_8) = SUB<M8, I8>;
DEF_ISEL(SUB_GPR8_IMMb_82r5_8) = SUB2<R8W, R8, I8>;
DEF_ISEL_Mn_Mn_In(SUB_MEMv_IMMb, SUB);
DEF_ISEL_Rn_Rn_In(SUB_GPRv_IMMb, SUB2);
DEF_ISEL(SUB_MEMb_GPR8_8) = SUB<M8, I8>;
DEF_ISEL(SUB_GPR8_GPR8_28_8) = SUB2<R8W, R8, R8>;
DEF_ISEL_Mn_Mn_Rn(SUB_MEMv_GPRv, SUB);
DEF_ISEL_Rn_Rn_Rn(SUB_GPRv_GPRv_29, SUB2);
DEF_ISEL(SUB_GPR8_GPR8_2A_8) = SUB2<R8W, R8, R8>;
DEF_ISEL(SUB_GPR8_MEMb_8) = SUB2<R8W, R8, M8>;
DEF_ISEL_Rn_Rn_Rn(SUB_GPRv_GPRv_2B, SUB2);
DEF_ISEL_Rn_Rn_Mn(SUB_GPRv_MEMv, SUB2);
DEF_ISEL(SUB_AL_IMMb_8) = SUB2<R8W, R8, I8>;
DEF_ISEL_Rn_Rn_In(SUB_OrAX_IMMz, SUB2);

DEF_ISEL(IMUL_MEMb_8) = Multiplier<SignedIntegerType>::MUL1_8<M8>;
DEF_ISEL(IMUL_GPR8_8) = Multiplier<SignedIntegerType>::MUL1_8<R8>;
DEF_ISEL(IMUL_MEMv_8) = Multiplier<SignedIntegerType>::MUL1_8<M8>;
DEF_ISEL(IMUL_MEMv_16) = Multiplier<SignedIntegerType>::MUL1_16<M16>;
DEF_ISEL(IMUL_MEMv_32) = Multiplier<SignedIntegerType>::MUL1_32<M32>;
IF_64BIT(DEF_ISEL(IMUL_MEMv_64) = Multiplier<SignedIntegerType>::MUL1_64<M64>;)
DEF_ISEL(IMUL_GPRv_8) = Multiplier<SignedIntegerType>::MUL1_8<R8>;
DEF_ISEL(IMUL_GPRv_16) = Multiplier<SignedIntegerType>::MUL1_16<R16>;
DEF_ISEL(IMUL_GPRv_32) = Multiplier<SignedIntegerType>::MUL1_32<R32>;
IF_64BIT(DEF_ISEL(IMUL_GPRv_64) = Multiplier<SignedIntegerType>::MUL1_64<R64>;)

// All dests are registers, albeit different ones from the sources.
DEF_ISEL_Rn_Mn_In(IMUL_GPRv_MEMv_IMMz, Multiplier<SignedIntegerType>::MUL3);
DEF_ISEL_Rn_Rn_In(IMUL_GPRv_GPRv_IMMz, Multiplier<SignedIntegerType>::MUL3);
DEF_ISEL_Rn_Mn_In(IMUL_GPRv_MEMv_IMMb, Multiplier<SignedIntegerType>::MUL3);
DEF_ISEL_Rn_Rn_In(IMUL_GPRv_GPRv_IMMb, Multiplier<SignedIntegerType>::MUL3);

// Two-operand, but dest is a register so turns into a three-operand.
DEF_ISEL_Rn_Rn_Mn(IMUL_GPRv_MEMv, Multiplier<SignedIntegerType>::MUL3);
DEF_ISEL_Rn_Rn_Rn(IMUL_GPRv_GPRv, Multiplier<SignedIntegerType>::MUL3);

DEF_ISEL(MUL_GPR8_8) = Multiplier<UnsignedIntegerType>::MUL1_8<R8>;
DEF_ISEL(MUL_MEMb_8) = Multiplier<UnsignedIntegerType>::MUL1_8<M8>;
DEF_ISEL(MUL_MEMv_8) = Multiplier<UnsignedIntegerType>::MUL1_8<M8>;
DEF_ISEL(MUL_MEMv_16) = Multiplier<UnsignedIntegerType>::MUL1_16<M16>;
DEF_ISEL(MUL_MEMv_32) = Multiplier<UnsignedIntegerType>::MUL1_32<M32>;
IF_64BIT(DEF_ISEL(MUL_MEMv_64) = Multiplier<UnsignedIntegerType>::MUL1_64<M64>;)
DEF_ISEL(MUL_GPRv_8) = Multiplier<UnsignedIntegerType>::MUL1_8<R8>;
DEF_ISEL(MUL_GPRv_16) = Multiplier<UnsignedIntegerType>::MUL1_16<R16>;
DEF_ISEL(MUL_GPRv_32) = Multiplier<UnsignedIntegerType>::MUL1_32<R32>;
IF_64BIT(DEF_ISEL(MUL_GPRv_64) = Multiplier<UnsignedIntegerType>::MUL1_64<R64>;)

DEF_ISEL(IDIV_MEMb_8) = Multiplier<SignedIntegerType>::DIV1_8<M8>;
DEF_ISEL(IDIV_GPR8_8) = Multiplier<SignedIntegerType>::DIV1_8<R8>;
DEF_ISEL(IDIV_MEMv_8) = Multiplier<SignedIntegerType>::DIV1_8<M8>;
DEF_ISEL(IDIV_MEMv_16) = Multiplier<SignedIntegerType>::DIV1_16<M16>;
DEF_ISEL(IDIV_MEMv_32) = Multiplier<SignedIntegerType>::DIV1_16<M32>;
IF_64BIT(DEF_ISEL(IDIV_MEMv_64) = Multiplier<SignedIntegerType>::DIV1_16<M64>;)
DEF_ISEL(IDIV_GPRv_8) = Multiplier<SignedIntegerType>::DIV1_8<R8>;
DEF_ISEL(IDIV_GPRv_16) = Multiplier<SignedIntegerType>::DIV1_16<R16>;
DEF_ISEL(IDIV_GPRv_32) = Multiplier<SignedIntegerType>::DIV1_16<R32>;
IF_64BIT(DEF_ISEL(IDIV_GPRv_64) = Multiplier<SignedIntegerType>::DIV1_16<R64>;)

DEF_ISEL(DIV_MEMb_8) = Multiplier<UnsignedIntegerType>::DIV1_8<M8>;
DEF_ISEL(DIV_GPR8_8) = Multiplier<UnsignedIntegerType>::DIV1_8<R8>;
DEF_ISEL(DIV_MEMv_8) = Multiplier<UnsignedIntegerType>::DIV1_8<M8>;
DEF_ISEL(DIV_MEMv_16) = Multiplier<UnsignedIntegerType>::DIV1_16<M16>;
DEF_ISEL(DIV_MEMv_32) = Multiplier<UnsignedIntegerType>::DIV1_16<M32>;
IF_64BIT(DEF_ISEL(DIV_MEMv_64) = Multiplier<UnsignedIntegerType>::DIV1_16<M64>;)
DEF_ISEL(DIV_GPRv_8) = Multiplier<UnsignedIntegerType>::DIV1_8<R8>;
DEF_ISEL(DIV_GPRv_16) = Multiplier<UnsignedIntegerType>::DIV1_16<R16>;
DEF_ISEL(DIV_GPRv_32) = Multiplier<UnsignedIntegerType>::DIV1_16<R32>;
IF_64BIT(DEF_ISEL(DIV_GPRv_64) = Multiplier<UnsignedIntegerType>::DIV1_16<R64>;)

DEF_ISEL(CMP_MEMb_IMMb_80r7_8) = CMP<M8, I8>;
DEF_ISEL(CMP_GPR8_IMMb_80r7_8) = CMP<R8, I8>;
DEF_ISEL_READONLY_Mn_In(CMP_MEMv_IMMz, CMP);
DEF_ISEL_READONLY_Rn_In(CMP_GPRv_IMMz, CMP);
DEF_ISEL(CMP_MEMb_IMMb_82r7_8) = CMP<M8, I8>;
DEF_ISEL(CMP_GPR8_IMMb_82r7_8) = CMP<R8, I8>;
DEF_ISEL_READONLY_Mn_In(CMP_MEMv_IMMb, CMP);
DEF_ISEL_READONLY_Rn_In(CMP_GPRv_IMMb, CMP);
DEF_ISEL(CMP_MEMb_GPR8_8) = CMP<M8, I8>;
DEF_ISEL(CMP_GPR8_GPR8_38_8) = CMP<R8, R8>;
DEF_ISEL_READONLY_Mn_Rn(CMP_MEMv_GPRv, CMP);
DEF_ISEL_READONLY_Rn_Rn(CMP_GPRv_GPRv_39, CMP);
DEF_ISEL(CMP_GPR8_GPR8_3A_8) = CMP<R8, R8>;
DEF_ISEL(CMP_GPR8_MEMb_8) = CMP<R8, M8>;
DEF_ISEL_READONLY_Rn_Rn(CMP_GPRv_GPRv_3B, CMP);
DEF_ISEL_READONLY_Rn_Mn(CMP_GPRv_MEMv, CMP);
DEF_ISEL(CMP_AL_IMMb_8) = CMP<R8, I8>;
DEF_ISEL_READONLY_Rn_In(CMP_OrAX_IMMz, CMP);

