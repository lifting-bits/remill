/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_X86_SEMANTICS_ROTATE_H_
#define MCSEMA_ARCH_X86_SEMANTICS_ROTATE_H_


namespace {
/*
inline static constexpr unsigned RotateCount(size_t size, unsigned count) {
  switch (size) {
    case 1: return (count & 0x1F) % 9;
    case 2: return (count & 0x1F) % 17;
    case 4: return count & 0x1F;
    case 8: return count & 0x3F;
    default:
      __builtin_unreachable();
      return 0;
  }
}
*/

template <typename D, typename S1, typename S2>
DEF_SEM(ROL, D dst, S1 src1, S2 src2) {
  typedef typename BaseType<S1>::Type T;
  enum : T {
    kSize = 8 * sizeof(T),
    kCountMask = 64 == kSize ? 0x3F : 0x1F
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
    if (1 == masked_count) {
      state.aflag.of = SignFlag(new_val) != state.aflag.cf;
    } else {
      state.aflag.of = __mcsema_undefined_bool();
    }
  } else {
    W(dst) = new_val;
  }

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


#endif  // MCSEMA_ARCH_X86_SEMANTICS_ROTATE_H_
