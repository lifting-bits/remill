/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_X86_SEMANTICS_ROTATE_H_
#define MCSEMA_ARCH_X86_SEMANTICS_ROTATE_H_

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(ROL, D dst, S1 src1, S2 src2) {
  typedef BASE_TYPE_OF(S1) T;
  enum : T {
    kSize = 8 * sizeof(T),
    kCountMask = 64 == kSize ? T(0x3F) : T(0x1F)
  };
  const auto count = static_cast<T>(R(src2));
  const auto masked_count = static_cast<T>(count & kCountMask);
  const auto temp_count = static_cast<T>(masked_count % kSize);
  const T val = R(src1);
  T new_val = val;
  if (temp_count) {
    new_val = (val << temp_count) | (val >> (kSize - temp_count));
    W(dst) = new_val;
    __mcsema_barrier_compiler();
    state.aflag.cf = new_val & 1;
    state.aflag.of = SignFlag(new_val) != state.aflag.cf;
    // OF undefined for `1 == temp_count`.
  } else {
    W(dst) = new_val;
  }
}

template <typename D, typename S1, typename S2>
DEF_SEM(ROR, D dst, S1 src1, S2 src2) {
  typedef BASE_TYPE_OF(S1) T;
  enum : T {
    kSize = 8 * sizeof(T),
    kCountMask = 64 == kSize ? T(0x3F) : T(0x1F)
  };
  const T val = R(src1);
  const auto count = static_cast<T>(R(src2));
  const auto masked_count = static_cast<T>(count & kCountMask);
  const auto temp_count = static_cast<T>(masked_count % kSize);
  T new_val = val;
  if (temp_count) {
    new_val = (val >> temp_count) | (val << (kSize - temp_count));
    W(dst) = new_val;
    __mcsema_barrier_compiler();
    state.aflag.cf = SignFlag(new_val);
    state.aflag.of = state.aflag.cf != SignFlag<T>(new_val << 1);
    // OF undefined for `1 == temp_count`.
  } else {
    W(dst) = new_val;
  }
}

template <typename D, typename S1, typename S2>
DEF_SEM(RORX, D dst, S1 src1, S2 src2) {
  typedef BASE_TYPE_OF(S1) T;
  enum : T {
    kSize = 8 * sizeof(T),
    kCountMask = 64 == kSize ? T(0x3F) : T(0x1F)
  };
  const T val = R(src1);
  const T count = static_cast<uint8_t>(R(src2)) & kCountMask;
  const T new_val = (val >> count) | (val << (kSize - count));
  W(dst) = new_val;
}

}  // namespace

DEF_ISEL(ROL_MEMb_IMMb) = ROL<M8W, M8, I8>;
DEF_ISEL(ROL_GPR8_IMMb) = ROL<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(ROL_MEMv_IMMb, ROL);
DEF_ISEL_RnW_Rn_In(ROL_GPRv_IMMb, ROL);
DEF_ISEL(ROL_MEMb_ONE) = ROL<M8W, M8, I8>;
DEF_ISEL(ROL_GPR8_ONE) = ROL<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(ROL_MEMv_ONE, ROL);
DEF_ISEL_RnW_Rn_In(ROL_GPRv_ONE, ROL);
DEF_ISEL(ROL_MEMb_CL) = ROL<M8W, M8, R8>;
DEF_ISEL(ROL_GPR8_CL) = ROL<R8W, R8, R8>;
DEF_ISEL_MnW_Mn_Rn(ROL_MEMv_CL, ROL);
DEF_ISEL_RnW_Rn_Rn(ROL_GPRv_CL, ROL);

DEF_ISEL(ROR_MEMb_IMMb) = ROR<M8W, M8, I8>;
DEF_ISEL(ROR_GPR8_IMMb) = ROR<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(ROR_MEMv_IMMb, ROR);
DEF_ISEL_RnW_Rn_In(ROR_GPRv_IMMb, ROR);
DEF_ISEL(ROR_MEMb_ONE) = ROR<M8W, M8, I8>;
DEF_ISEL(ROR_GPR8_ONE) = ROR<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(ROR_MEMv_ONE, ROR);
DEF_ISEL_RnW_Rn_In(ROR_GPRv_ONE, ROR);
DEF_ISEL(ROR_MEMb_CL) = ROR<M8W, M8, R8>;
DEF_ISEL(ROR_GPR8_CL) = ROR<R8W, R8, R8>;
DEF_ISEL_MnW_Mn_Rn(ROR_MEMv_CL, ROR);
DEF_ISEL_RnW_Rn_Rn(ROR_GPRv_CL, ROR);

DEF_ISEL(RORX_VGPR32d_VGPR32d_IMMb) = RORX<R32W, R32, I8>;
DEF_ISEL(RORX_VGPR32d_MEMd_IMMb) = RORX<R32W, M32, I8>;
DEF_ISEL(RORX_VGPR64q_VGPR64q_IMMb) = RORX<R64W, R64, I8>;
DEF_ISEL(RORX_VGPR64q_MEMq_IMMb) = RORX<R64W, M64, I8>;

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(RCL, D dst, S1 src1, S2 src2) {
  typedef BASE_TYPE_OF(S1) T;
  enum : T {
    kSize = 8 * sizeof(T),
    kCountMask = 64 == kSize ? T(0x3F) : T(0x1F),
    kMod = kSize < 32 ? kSize + 1 : (kCountMask + 1)
  };
  const auto count = static_cast<T>(R(src2));
  const auto masked_count = static_cast<T>(count & kCountMask);
  const auto temp_count = static_cast<T>(masked_count % kMod);
  const T val = R(src1);
  const T carry = state.aflag.cf ? 1 : 0;
  T new_val = val;

  // Note: we split the right shift into two to avoid UB.
  if (temp_count) {
    const T right = val >> (kSize - temp_count);
    new_val = T(val << temp_count) |
              T(carry << T(temp_count - 1)) |
              T(right >> 1);
    W(dst) = new_val;
    __mcsema_barrier_compiler();
    state.aflag.cf = SignFlag<T>(val << (temp_count - 1));
    state.aflag.of = SignFlag(new_val) != state.aflag.cf;
    // OF undefined for `1 == temp_count`.
  } else {
    W(dst) = new_val;
  }
}

template <typename D, typename S1, typename S2>
DEF_SEM(RCR, D dst, S1 src1, S2 src2) {
  typedef BASE_TYPE_OF(S1) T;
  enum : T {
    kSize = 8 * sizeof(T),
    kCountMask = 64 == kSize ? T(0x3F) : T(0x1F),
    kMod = kSize < 32 ? kSize + 1 : (kCountMask + 1)
  };
  const T val = R(src1);
  const T carry = state.aflag.cf ? 1 : 0;
  const auto count = static_cast<T>(R(src2));
  const auto masked_count = static_cast<T>(count & kCountMask);
  const auto temp_count = static_cast<T>(masked_count % kMod);
  T new_val = val;
  if (temp_count) {
    new_val = (val >> temp_count) | (val << (kSize - temp_count));
    W(dst) = new_val;
    __mcsema_barrier_compiler();
    state.aflag.cf = SignFlag(new_val);
    state.aflag.of = SignFlag(new_val) != state.aflag.cf;
    // OF undefined for `1 == temp_count`.
  } else {
    W(dst) = new_val;
  }
}

}  // namespace

DEF_ISEL(RCL_MEMb_IMMb) = RCL<M8W, M8, I8>;
DEF_ISEL(RCL_GPR8_IMMb) = RCL<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(RCL_MEMv_IMMb, RCL);
DEF_ISEL_RnW_Rn_In(RCL_GPRv_IMMb, RCL);
DEF_ISEL(RCL_MEMb_ONE) = RCL<M8W, M8, I8>;
DEF_ISEL(RCL_GPR8_ONE) = RCL<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(RCL_MEMv_ONE, RCL);
DEF_ISEL_RnW_Rn_In(RCL_GPRv_ONE, RCL);
DEF_ISEL(RCL_MEMb_CL) = RCL<M8W, M8, R8>;
DEF_ISEL(RCL_GPR8_CL) = RCL<R8W, R8, R8>;
DEF_ISEL_MnW_Mn_Rn(RCL_MEMv_CL, RCL);
DEF_ISEL_RnW_Rn_Rn(RCL_GPRv_CL, RCL);


#endif  // MCSEMA_ARCH_X86_SEMANTICS_ROTATE_H_
