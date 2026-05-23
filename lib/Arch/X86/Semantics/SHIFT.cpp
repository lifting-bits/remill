/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

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
    WriteZExt(dst, val);
    return memory;  // No flags affected.
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
  return memory;
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
    WriteZExt(dst, uval);
    return memory;  // No flags affected.
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
  return memory;
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
    WriteZExt(dst, val);
    return memory;  // No flags affected.
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
    auto msb = SignFlag(res);
    new_of = BUndefined();  // Undefined, hard to understand possible values.
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
  Write(FLAG_AF, BUndefined());  // Undefined, experimentally 0.
  Write(FLAG_ZF, ZeroFlag(new_val));
  Write(FLAG_SF, SignFlag(new_val));
  Write(FLAG_OF, new_of);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(SHLX, D dst, S1 src1, S2 src2) {
  auto val = Read(src1);
  auto shift = ZExtTo<S1>(TruncTo<uint8_t>(Read(src2)));
  auto long_mask = Literal<S1>(0x3F);
  auto short_mask = Literal<S1>(0x1F);
  auto op_size = BitSizeOf(src1);
  auto shift_mask = Select(UCmpEq(op_size, 64), long_mask, short_mask);
  auto masked_shift = UAnd(shift, shift_mask);
  WriteZExt(dst, UShl(val, masked_shift));
  return memory;
}

// BMI2 variable shifts do not write flags and take the count from the low byte
// of the third operand, masked according to the data operand width.
template <typename D, typename S1, typename S2>
DEF_SEM(SHRX, D dst, S1 src1, S2 src2) {
  auto val = Read(src1);
  auto shift = ZExtTo<S1>(TruncTo<uint8_t>(Read(src2)));
  auto long_mask = Literal<S1>(0x3F);
  auto short_mask = Literal<S1>(0x1F);
  auto op_size = BitSizeOf(src1);
  auto shift_mask = Select(UCmpEq(op_size, 64), long_mask, short_mask);
  auto masked_shift = UAnd(shift, shift_mask);
  WriteZExt(dst, UShr(val, masked_shift));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(SARX, D dst, S1 src1, S2 src2) {
  auto val = Read(src1);
  auto shift = ZExtTo<S1>(TruncTo<uint8_t>(Read(src2)));
  auto long_mask = Literal<S1>(0x3F);
  auto short_mask = Literal<S1>(0x1F);
  auto op_size = BitSizeOf(src1);
  auto shift_mask = Select(UCmpEq(op_size, 64), long_mask, short_mask);
  auto masked_shift = UAnd(shift, shift_mask);
  WriteZExt(dst, Unsigned(SShr(Signed(val), Signed(masked_shift))));
  return memory;
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

DEF_ISEL(SHLX_GPR32d_MEMd_GPR32d) = SHLX<R32W, M32, R32>;
DEF_ISEL(SHLX_GPR32d_GPR32d_GPR32d) = SHLX<R32W, R32, R32>;
DEF_ISEL(SHLX_VGPR32d_MEMd_VGPR32d) = SHLX<R32W, M32, R32>;
DEF_ISEL(SHLX_VGPR32d_VGPR32d_VGPR32d) = SHLX<R32W, R32, R32>;
IF_64BIT(DEF_ISEL(SHLX_GPR64q_MEMq_GPR64q) = SHLX<R64W, M64, R64>;)
IF_64BIT(DEF_ISEL(SHLX_GPR64q_GPR64q_GPR64q) = SHLX<R64W, R64, R64>;)
IF_64BIT(DEF_ISEL(SHLX_VGPR64q_MEMq_VGPR64q) = SHLX<R64W, M64, R64>;)
IF_64BIT(DEF_ISEL(SHLX_VGPR64q_VGPR64q_VGPR64q) = SHLX<R64W, R64, R64>;)

DEF_ISEL(SHRX_GPR32d_MEMd_GPR32d) = SHRX<R32W, M32, R32>;
DEF_ISEL(SHRX_GPR32d_GPR32d_GPR32d) = SHRX<R32W, R32, R32>;
DEF_ISEL(SHRX_VGPR32d_MEMd_VGPR32d) = SHRX<R32W, M32, R32>;
DEF_ISEL(SHRX_VGPR32d_VGPR32d_VGPR32d) = SHRX<R32W, R32, R32>;
IF_64BIT(DEF_ISEL(SHRX_GPR64q_MEMq_GPR64q) = SHRX<R64W, M64, R64>;)
IF_64BIT(DEF_ISEL(SHRX_GPR64q_GPR64q_GPR64q) = SHRX<R64W, R64, R64>;)
IF_64BIT(DEF_ISEL(SHRX_VGPR64q_MEMq_VGPR64q) = SHRX<R64W, M64, R64>;)
IF_64BIT(DEF_ISEL(SHRX_VGPR64q_VGPR64q_VGPR64q) = SHRX<R64W, R64, R64>;)

DEF_ISEL(SARX_GPR32d_MEMd_GPR32d) = SARX<R32W, M32, R32>;
DEF_ISEL(SARX_GPR32d_GPR32d_GPR32d) = SARX<R32W, R32, R32>;
DEF_ISEL(SARX_VGPR32d_MEMd_VGPR32d) = SARX<R32W, M32, R32>;
DEF_ISEL(SARX_VGPR32d_VGPR32d_VGPR32d) = SARX<R32W, R32, R32>;
IF_64BIT(DEF_ISEL(SARX_GPR64q_MEMq_GPR64q) = SARX<R64W, M64, R64>;)
IF_64BIT(DEF_ISEL(SARX_GPR64q_GPR64q_GPR64q) = SARX<R64W, R64, R64>;)
IF_64BIT(DEF_ISEL(SARX_VGPR64q_MEMq_VGPR64q) = SARX<R64W, M64, R64>;)
IF_64BIT(DEF_ISEL(SARX_VGPR64q_VGPR64q_VGPR64q) = SARX<R64W, R64, R64>;)

namespace {

template <typename T>
ALWAYS_INLINE static uint8_t SHRDCarryFlag(T concat, T count) {
  auto one = Literal<T>(1);
  return UCmpEq(UAnd(UShr(concat, USub(count, one)), one), one);
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
    WriteZExt(dst, val1);
    return memory;
  }

  auto wide_op_size = ZExt(op_size);
  auto wide_shift = ZExt(masked_shift);

  if (UCmpLt(op_size, masked_shift)) {
    auto excess = USub(masked_shift, op_size);
    auto wide_excess = ZExt(excess);
    auto src_concat = UOr(UShl(ZExt(val2), wide_op_size), ZExt(val2));
    auto res = TruncTo<S1>(UShr(src_concat, wide_excess));

    WriteZExt(dst, res);

    Write(FLAG_CF, false);
    Write(FLAG_PF, ParityFlag(res));
    Write(FLAG_AF, BUndefined());
    Write(FLAG_ZF, ZeroFlag(res));
    Write(FLAG_SF, SignFlag(res));
    Write(FLAG_OF, BUndefined());
    return memory;
  }

  auto concat = UOr(UShl(ZExt(val2), wide_op_size), ZExt(val1));
  auto res = TruncTo<S1>(UShr(concat, wide_shift));

  WriteZExt(dst, res);

  Write(FLAG_CF, SHRDCarryFlag(concat, wide_shift));
  Write(FLAG_PF, ParityFlag(res));
  Write(FLAG_AF, BUndefined());
  Write(FLAG_ZF, ZeroFlag(res));
  Write(FLAG_SF, SignFlag(res));
  if (UCmpEq(masked_shift, Literal<S1>(1))) {
    Write(FLAG_OF, BXor(SignFlag(val1), FLAG_SF));
  } else {
    Write(FLAG_OF, BUndefined());
  }
  return memory;
}

}  // namespace

DEF_ISEL_MnW_Mn_Rn_In(SHRD_MEMv_GPRv_IMMb, SHRD);
DEF_ISEL_RnW_Rn_Rn_In(SHRD_GPRv_GPRv_IMMb, SHRD);
DEF_ISEL_MnW_Mn_Rn_Rn(SHRD_MEMv_GPRv_CL, SHRD);
DEF_ISEL_RnW_Rn_Rn_Rn(SHRD_GPRv_GPRv_CL, SHRD);

namespace {

template <typename T>
ALWAYS_INLINE static uint8_t SHLDCarryFlag(T concat, T op_size, T count) {
  auto one = Literal<T>(1);
  auto two_op_size = UAdd(op_size, op_size);
  auto bit_index = USub(two_op_size, count);
  return UCmpEq(UAnd(UShr(concat, bit_index), one), one);
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
    WriteZExt(dst, val1);
    return memory;
  }

  auto wide_op_size = ZExt(op_size);
  auto wide_shift = ZExt(masked_shift);

  if (UCmpLt(op_size, masked_shift)) {
    auto excess = USub(masked_shift, op_size);
    auto wide_excess = ZExt(excess);
    auto src_concat = UOr(UShl(ZExt(val2), wide_op_size), ZExt(val2));
    auto res = TruncTo<S1>(UShr(UShl(src_concat, wide_excess), wide_op_size));

    WriteZExt(dst, res);

    Write(FLAG_CF, false);
    Write(FLAG_PF, ParityFlag(res));
    Write(FLAG_AF, BUndefined());
    Write(FLAG_ZF, ZeroFlag(res));
    Write(FLAG_SF, SignFlag(res));
    Write(FLAG_OF, BUndefined());
    return memory;
  }

  auto concat = UOr(UShl(ZExt(val1), wide_op_size), ZExt(val2));
  auto res = TruncTo<S1>(UShr(UShl(concat, wide_shift), wide_op_size));

  WriteZExt(dst, res);

  Write(FLAG_CF, SHLDCarryFlag(concat, wide_op_size, wide_shift));
  Write(FLAG_PF, ParityFlag(res));
  Write(FLAG_AF, BUndefined());
  Write(FLAG_ZF, ZeroFlag(res));
  Write(FLAG_SF, SignFlag(res));
  if (UCmpEq(masked_shift, Literal<S1>(1))) {
    Write(FLAG_OF, BXor(SignFlag(val1), FLAG_SF));
  } else {
    Write(FLAG_OF, BUndefined());
  }
  return memory;
}

}  // namespace

DEF_ISEL_MnW_Mn_Rn_In(SHLD_MEMv_GPRv_IMMb, SHLD);
DEF_ISEL_RnW_Rn_Rn_In(SHLD_GPRv_GPRv_IMMb, SHLD);
DEF_ISEL_MnW_Mn_Rn_Rn(SHLD_MEMv_GPRv_CL, SHLD);
DEF_ISEL_RnW_Rn_Rn_Rn(SHLD_GPRv_GPRv_CL, SHLD);

namespace {

template <typename D>
DEF_SEM(PSLLDQ, D dst, V128 src1, I8 src2) {
  uint8v16_t src1_vec = UReadV8(src1);
  uint8v16_t dst_vec = {};
  size_t shift_amount = std::min<size_t>(ZExtTo<size_t>(Read(src2)), 16);
  _Pragma("unroll") for (size_t i = 0; i < 16; ++i) {
    if (i < (16 - shift_amount)) {
      dst_vec = UInsertV8(dst_vec, i + shift_amount, UExtractV8(src1_vec, i));
    }
  }
  UWriteV8(dst, dst_vec);
  return memory;
}

#if HAS_FEATURE_AVX
template <typename D>
DEF_SEM(VPSLLDQ, D dst, V256 src1, I8 src2) {
  uint8v32_t src1_vec = UReadV8(src1);
  uint8v32_t dst_vec = {};
  size_t shift_amount = std::min<size_t>(ZExtTo<size_t>(Read(src2)), 16);

  _Pragma("unroll") for (size_t i = 0, j = 16; i < 16; ++i, ++j) {
    if (i < (16 - shift_amount)) {
      dst_vec = UInsertV8(dst_vec, i + shift_amount, UExtractV8(src1_vec, i));
      dst_vec = UInsertV8(dst_vec, j + shift_amount, UExtractV8(src1_vec, j));
    }
  }
  UWriteV8(dst, dst_vec);
  return memory;
}
#endif  // HAS_FEATURE_AVX

}  // namespace

DEF_ISEL(PSLLDQ_XMMdq_IMMb) = PSLLDQ<V128W>;
IF_AVX(DEF_ISEL(VPSLLDQ_XMMdq_XMMdq_IMMb) = PSLLDQ<VV128W>;)
IF_AVX(DEF_ISEL(VPSLLDQ_YMMqq_YMMqq_IMMb) = VPSLLDQ<VV256W>;)

/*
3749 VPSLLDQ VPSLLDQ_XMMu8_XMMu8_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES:
3750 VPSLLDQ VPSLLDQ_XMMu8_MEMu8_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: DISP8_FULLMEM
3751 VPSLLDQ VPSLLDQ_YMMu8_YMMu8_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES:
3752 VPSLLDQ VPSLLDQ_YMMu8_MEMu8_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: DISP8_FULLMEM
3753 VPSLLDQ VPSLLDQ_ZMMu8_ZMMu8_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES:
3754 VPSLLDQ VPSLLDQ_ZMMu8_MEMu8_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: DISP8_FULLMEM
 */
