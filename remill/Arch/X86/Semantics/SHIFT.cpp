/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_X86_SEMANTICS_SHIFT_H_
#define REMILL_ARCH_X86_SEMANTICS_SHIFT_H_

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(SHR, D dst, S1 src1, S2 src2) {
  auto val = Read(src1);
  auto shift = Read(src2);
  auto long_mask = Literal<S1>(0x3F);
  auto short_mask = Literal<S1>(0x1F);
  auto op_size = BitSizeOf(src1);
  auto shift_mask = Select(UCmpEq(op_size, 64), long_mask, short_mask);
  auto masked_shift = UAnd(shift, shift_mask);
  if (UCmpEq(masked_shift, 0)) {
    return;  // No flags affected.
  }
  auto new_val = val;
  auto new_of = false;
  auto new_cf = false;

  if (UCmpEq(masked_shift, 1)) {
    new_of = SignFlag(val);
    new_cf = UCmpEq(UAnd(val, 1), 1);
    new_val = UShr(val, 1);

  } else if (UCmpLt(masked_shift, op_size)) {
    auto res = UShr(val, USub(masked_shift, 1));
    new_of = BUndefined();
    new_cf = UCmpEq(UAnd(res, 1), 1);
    new_val = UShr(res, 1);

  } else {
    new_of = BUndefined();
    new_cf = BUndefined();
    new_val = 0;
  }
  WriteZExt(dst, new_val);
  Write(FLAG_CF, new_cf);
  Write(FLAG_PF, ParityFlag(new_val));
  Write(FLAG_AF, BUndefined());
  Write(FLAG_ZF, ZeroFlag(new_val));
  Write(FLAG_SF, false);
  Write(FLAG_OF, new_of);
}

template <typename D, typename S1, typename S2>
DEF_SEM(SAR, D dst, S1 src1, S2 src2) {
  auto uval = Read(src1);
  auto shift = Read(src2);
  auto val = Signed(uval);
  auto one = SLiteral<S1>(1);
  auto long_mask = Literal<S1>(0x3F);
  auto short_mask = Literal<S1>(0x1F);
  auto op_size = BitSizeOf(src1);
  auto shift_mask = Select(UCmpEq(op_size, 64), long_mask, short_mask);
  auto masked_shift = UAnd(shift, shift_mask);
  if (UCmpEq(masked_shift, 0)) {
    return;  // No flags affected.
  }
  auto new_val = uval;
  auto new_of = false;
  auto new_cf = false;

  if (UCmpEq(masked_shift, 1)) {
    new_of = false;
    new_cf = UCmpEq(UAnd(uval, 1), 1);
    new_val = Unsigned(SShr(val, one));

  } else if (UCmpLt(masked_shift, op_size)) {
    auto res = SShr(val, Signed(USub(masked_shift, 1)));
    new_of = BUndefined();
    new_cf = SCmpEq(SAnd(res, one), one);
    new_val = Unsigned(SShr(res, one));

  } else {
    new_of = BUndefined();
    new_cf = BUndefined();
    if (SignFlag(val)) {
      new_val = Maximize(uval);
    } else {
      new_val = 0;
    }
  }

  WriteZExt(dst, new_val);
  Write(FLAG_CF, new_cf);
  Write(FLAG_PF, ParityFlag(new_val));
  Write(FLAG_AF, BUndefined());
  Write(FLAG_ZF, ZeroFlag(new_val));
  Write(FLAG_SF, SignFlag(new_val));
  Write(FLAG_OF, new_of);
}

template <typename D, typename S1, typename S2>
DEF_SEM(SHL, D dst, S1 src1, S2 src2) {
  auto val = Read(src1);
  auto shift = Read(src2);

  auto long_mask = Literal<S1>(0x3F);
  auto short_mask = Literal<S1>(0x1F);
  auto op_size = BitSizeOf(src1);
  auto shift_mask = Select(UCmpEq(op_size, 64), long_mask, short_mask);
  auto masked_shift = UAnd(shift, shift_mask);

  if (UCmpEq(masked_shift, 0)) {
    return;  // No flags affected.
  }

  auto new_val = val;
  auto new_of = false;
  auto new_cf = false;

  if (UCmpEq(masked_shift, 1)) {
    auto res = UShl(val, 1);
    auto msb = SignFlag(val);
    auto new_msb = SignFlag(res);

    new_of = BXor(msb, new_msb);
    new_cf = msb;
    new_val = res;

  } else if (UCmpLt(masked_shift, op_size)) {
    auto res = UShl(val, USub(masked_shift, 1));
    const auto msb = SignFlag(res);
    new_of = BUndefined();
    new_cf = msb;
    new_val = UShl(res, 1);
  } else {
    new_of = BUndefined();
    new_cf = BUndefined();
    new_val = 0;
  }

  WriteZExt(dst, new_val);
  Write(FLAG_CF, new_cf);
  Write(FLAG_PF, ParityFlag(new_val));
  Write(FLAG_AF, BUndefined());
  Write(FLAG_ZF, ZeroFlag(new_val));
  Write(FLAG_SF, SignFlag(new_val));
  Write(FLAG_OF, new_of);
}
}  // namespace

DEF_ISEL(SHR_MEMb_IMMb) = SHR<M8W, M8, I8>;
DEF_ISEL(SHR_GPR8_IMMb) = SHR<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(SHR_MEMv_IMMb, SHR);
DEF_ISEL_RnW_Rn_In(SHR_GPRv_IMMb, SHR);
DEF_ISEL(SHR_MEMb_ONE) = SHR<M8W, M8, I8>;
DEF_ISEL(SHR_GPR8_ONE) = SHR<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(SHR_MEMv_ONE, SHR);
DEF_ISEL_RnW_Rn_In(SHR_GPRv_ONE, SHR);
DEF_ISEL(SHR_MEMb_CL) = SHR<M8W, M8, R8>;
DEF_ISEL(SHR_GPR8_CL) = SHR<R8W, R8, R8>;
DEF_ISEL_MnW_Mn_Rn(SHR_MEMv_CL, SHR);
DEF_ISEL_RnW_Rn_Rn(SHR_GPRv_CL, SHR);

DEF_ISEL(SAR_MEMb_IMMb) = SAR<M8W, M8, I8>;
DEF_ISEL(SAR_GPR8_IMMb) = SAR<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(SAR_MEMv_IMMb, SAR);
DEF_ISEL_RnW_Rn_In(SAR_GPRv_IMMb, SAR);
DEF_ISEL(SAR_MEMb_ONE) = SAR<M8W, M8, I8>;
DEF_ISEL(SAR_GPR8_ONE) = SAR<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(SAR_MEMv_ONE, SAR);
DEF_ISEL_RnW_Rn_In(SAR_GPRv_ONE, SAR);
DEF_ISEL(SAR_MEMb_CL) = SAR<M8W, M8, R8>;
DEF_ISEL(SAR_GPR8_CL) = SAR<R8W, R8, R8>;
DEF_ISEL_MnW_Mn_Rn(SAR_MEMv_CL, SAR);
DEF_ISEL_RnW_Rn_Rn(SAR_GPRv_CL, SAR);

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
NEVER_INLINE static uint8_t SHRDCarryFlag(T val, T count) {
  __remill_defer_inlining();
  return UCmpEq(UAnd(UShr(val, USub(count, 1)), 1), 1);
}

template <typename D, typename S1, typename S2, typename S3>
DEF_SEM(SHRD, D dst, S1 src1, S2 src2, S3 src3) {
  auto val1 = Read(src1);
  auto val2 = Read(src2);
  auto shift = Read(src3);

  auto long_mask = Literal<S1>(0x3F);
  auto short_mask = Literal<S1>(0x1F);
  auto op_size = BitSizeOf(src1);
  auto shift_mask = Select(UCmpEq(op_size, 64), long_mask, short_mask);
  auto masked_shift = UAnd(shift, shift_mask);

  if (UCmpEq(masked_shift, 0)) {
    return;

  } else if (UCmpLt(op_size, masked_shift)) {
    ClearArithFlags();
    // `dst` is undefined; leave as-is.
    //
    // TODO(pag): Update `dst` anyway because it may be readable but not
    //            writable?
    return;
  }

  auto left = UShl(val2, USub(op_size, masked_shift));
  auto right = UShr(val1, masked_shift);
  auto res = UOr(left, right);

  WriteZExt(dst, res);

  Write(FLAG_CF, SHRDCarryFlag(val1, masked_shift));
  Write(FLAG_PF, ParityFlag(res));
  Write(FLAG_AF, BUndefined());
  Write(FLAG_ZF, ZeroFlag(res));
  Write(FLAG_SF, SignFlag(res));
  Write(FLAG_OF, BXor(SignFlag(val1), FLAG_SF));
  // OF undefined for `1 == temp_count`.
}

}  // namespace

DEF_ISEL_MnW_Mn_Rn_In(SHRD_MEMv_GPRv_IMMb, SHRD);
DEF_ISEL_RnW_Rn_Rn_In(SHRD_GPRv_GPRv_IMMb, SHRD);
DEF_ISEL_MnW_Mn_Rn_Rn(SHRD_MEMv_GPRv_CL, SHRD);
DEF_ISEL_RnW_Rn_Rn_Rn(SHRD_GPRv_GPRv_CL, SHRD);

namespace {

template <typename T>
NEVER_INLINE static uint8_t SHLDCarryFlag(T val, T count) {
  __remill_defer_inlining();
  return UCmpEq(UAnd(UShr(val, USub(BitSizeOf(count), count)), 1), 1);
}

template <typename D, typename S1, typename S2, typename S3>
DEF_SEM(SHLD, D dst, S1 src1, S2 src2, S3 src3) {
  auto val1 = Read(src1);
  auto val2 = Read(src2);
  auto shift = Read(src3);

  auto long_mask = Literal<S1>(0x3F);
  auto short_mask = Literal<S1>(0x1F);
  auto op_size = BitSizeOf(src1);
  auto shift_mask = Select(UCmpEq(op_size, 64), long_mask, short_mask);
  auto masked_shift = UAnd(shift, shift_mask);

  if (UCmpEq(masked_shift, 0)) {
    return;

  } else if (UCmpLt(op_size, masked_shift)) {
    ClearArithFlags();
    // `dst` is undefined; leave as-is.
    //
    // TODO(pag): Update `dst` anyway because it may be readable but not
    //            writable?
    return;
  }

  auto left = UShl(val1, masked_shift);
  auto right = UShr(val2, USub(op_size, masked_shift));
  auto res = UOr(left, right);

  WriteZExt(dst, res);

  Write(FLAG_CF, SHLDCarryFlag(val1, masked_shift));
  Write(FLAG_PF, ParityFlag(res));
  Write(FLAG_AF, BUndefined());
  Write(FLAG_ZF, ZeroFlag(res));
  Write(FLAG_SF, SignFlag(res));
  Write(FLAG_OF, BXor(SignFlag(val1), FLAG_SF));
  // OF undefined for `1 == temp_count`.
}

}  // namespace

DEF_ISEL_MnW_Mn_Rn_In(SHLD_MEMv_GPRv_IMMb, SHLD);
DEF_ISEL_RnW_Rn_Rn_In(SHLD_GPRv_GPRv_IMMb, SHLD);
DEF_ISEL_MnW_Mn_Rn_Rn(SHLD_MEMv_GPRv_CL, SHLD);
DEF_ISEL_RnW_Rn_Rn_Rn(SHLD_GPRv_GPRv_CL, SHLD);

#endif  // REMILL_ARCH_X86_SEMANTICS_SHIFT_H_
