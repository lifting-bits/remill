/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_X86_SEMANTICS_SHIFT_H_
#define REMILL_ARCH_X86_SEMANTICS_SHIFT_H_


namespace {

template <template <typename> class Converter>
struct ShiftRight {
  template <typename D, typename S1, typename S2>
  DEF_SEM(DO, D dst, S1 src1_, S2 src2_) {
    typedef BASE_TYPE_OF(S1) UT;
    typedef typename Converter<UT>::Type T;
    enum : UT {
      // The mask is based on the REX.W prefix being used and 64-bit mode. We
      // determine this based on the source being a 64-bit operand.
      //
      // Note: The mask will be 31 even for 16- and 8-bit operands.
      kArchMask = 8 == sizeof(T) ? UT(0x3FU) : UT(0x1FU),
      kNumBits = sizeof(T) * 8
    };

    const UT shift = R(src2_) & kArchMask;
    if (UT(0) == shift) {
      return;  // No flags affected.
    }

    const auto val = static_cast<T>(R(src1_));
    T new_val = T(0);
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

      new_of = __remill_undefined_bool();
      new_cf = res & 1;
      new_val = res >> 1;

    } else {
      new_of = __remill_undefined_bool();
      new_cf = __remill_undefined_bool();
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

    __remill_barrier_compiler();

    state.aflag.cf = new_cf;
    state.aflag.pf = ParityFlag(new_val);
    state.aflag.af = __remill_undefined_bool();
    state.aflag.zf = ZeroFlag(new_val);
    state.aflag.sf = std::is_signed<T>::value ? SignFlag(new_val) : false;
    state.aflag.of = new_of;
  }
};

template <typename D, typename S1, typename S2>
DEF_SEM(SHL, D dst, S1 src1_, S2 src2_) {
  typedef BASE_TYPE_OF(S1) T;
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

    new_of = __remill_undefined_bool();
    new_cf = msb;
    new_val = res << 1;

  } else {
    new_of = __remill_undefined_bool();
    new_cf = __remill_undefined_bool();
    new_val = 0;
  }

  W(dst) = new_val;

  __remill_barrier_compiler();

  state.aflag.cf = new_cf;
  state.aflag.pf = ParityFlag(new_val);
  state.aflag.af = __remill_undefined_bool();
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

namespace {

template <typename T>
NEVER_INLINE static bool SHRDCarryFlag(T val, T count) {
  __remill_defer_inlining();
  return (val >> (count - 1)) & 1;
}

template <typename D, typename S1, typename S2, typename S3>
DEF_SEM(SHRD, D dst, S1 src1, S2 src2, S3 count_) {
  typedef BASE_TYPE_OF(S1) T;
  enum : T {
    kMod = static_cast<T>(8 == sizeof(T) ? 64 : 32),
    kSize = static_cast<T>(sizeof(T) * 8)
  };
  const T count = static_cast<T>(R(count_)) % kMod;
  if (!count) {
    return;
  }
  if (kSize < count) {
    CLEAR_AFLAGS();
    W(dst) = U(dst);  // Store and undefined value.
    return;
  }
  const T src = R(src1);
  const T right = src >> count;
  const T left = R(src2) << (kSize - count);
  const T res = left | right;
  W(dst) = res;
  __remill_barrier_compiler();
  state.aflag.cf = SHRDCarryFlag(src, count);
  state.aflag.sf = SignFlag(res);
  state.aflag.zf = ZeroFlag(res);
  state.aflag.pf = ParityFlag(res);
  state.aflag.af = __remill_undefined_bool();
  state.aflag.of = SignFlag(src) != state.aflag.sf;
  // OF undefined for `1 == temp_count`.
}

}  // namespace

DEF_ISEL_MnW_Mn_Rn_In(SHRD_MEMv_GPRv_IMMb, SHRD);
DEF_ISEL_RnW_Rn_Rn_In(SHRD_GPRv_GPRv_IMMb, SHRD);
DEF_ISEL_MnW_Mn_Rn_Rn(SHRD_MEMv_GPRv_CL, SHRD);
DEF_ISEL_RnW_Rn_Rn_Rn(SHRD_GPRv_GPRv_CL, SHRD);

namespace {

template <typename T>
NEVER_INLINE static bool SHLDCarryFlag(T val, T count) {
  __remill_defer_inlining();
  return (val >> ((8 * sizeof(T)) - count)) & 1;
}

template <typename D, typename S1, typename S2, typename S3>
DEF_SEM(SHLD, D dst, S1 src1, S2 src2, S3 count_) {
  typedef BASE_TYPE_OF(S1) T;
  enum : T {
    kMod = static_cast<T>(8 == sizeof(T) ? 64 : 32),
    kSize = static_cast<T>(sizeof(T) * 8)
  };
  const T count = static_cast<T>(R(count_)) % kMod;
  if (!count) {
    return;
  }
  if (kSize < count) {
    CLEAR_AFLAGS();
    W(dst) = U(dst);  // Store and undefined value.
    return;
  }
  const T src = R(src1);
  const T left = src << count;
  const T right = R(src2) >> (kSize - count);
  const T res = left | right;
  W(dst) = res;
  __remill_barrier_compiler();
  state.aflag.cf = SHLDCarryFlag(src, count);
  state.aflag.sf = SignFlag(res);
  state.aflag.zf = ZeroFlag(res);
  state.aflag.pf = ParityFlag(res);
  state.aflag.af = __remill_undefined_bool();
  state.aflag.of = SignFlag(src) != state.aflag.sf;
  // OF undefined for `1 == temp_count`.
}

}  // namespace

DEF_ISEL_MnW_Mn_Rn_In(SHLD_MEMv_GPRv_IMMb, SHLD);
DEF_ISEL_RnW_Rn_Rn_In(SHLD_GPRv_GPRv_IMMb, SHLD);
DEF_ISEL_MnW_Mn_Rn_Rn(SHLD_MEMv_GPRv_CL, SHLD);
DEF_ISEL_RnW_Rn_Rn_Rn(SHLD_GPRv_GPRv_CL, SHLD);

#endif  // REMILL_ARCH_X86_SEMANTICS_SHIFT_H_
