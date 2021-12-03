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

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(SUB, D dst, S1 src1, S2 src2) {
  WriteZExt(dst, USub(Read(src1), Read(src2)));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(ADD, D dst, S1 src1, S2 src2) {
  WriteZExt(dst, UAdd(Read(src1), Read(src2)));
  return memory;
}
}  // namespace

DEF_ISEL(ADD_32_ADDSUB_IMM) = ADD<R32W, R32, I32>;
DEF_ISEL(ADD_64_ADDSUB_IMM) = ADD<R64W, R64, I64>;
DEF_ISEL(ADD_32_ADDSUB_SHIFT) = ADD<R32W, R32, I32>;
DEF_ISEL(ADD_64_ADDSUB_SHIFT) = ADD<R64W, R64, I64>;
DEF_ISEL(ADD_32_ADDSUB_EXT) = ADD<R32W, R32, I32>;
DEF_ISEL(ADD_64_ADDSUB_EXT) = ADD<R64W, R64, I64>;

DEF_ISEL(SUB_32_ADDSUB_IMM) = SUB<R32W, R32, I32>;
DEF_ISEL(SUB_64_ADDSUB_IMM) = SUB<R64W, R64, I64>;
DEF_ISEL(SUB_32_ADDSUB_SHIFT) = SUB<R32W, R32, I32>;
DEF_ISEL(SUB_64_ADDSUB_SHIFT) = SUB<R64W, R64, I64>;
DEF_ISEL(SUB_32_ADDSUB_EXT) = SUB<R32W, R32, I32>;
DEF_ISEL(SUB_64_ADDSUB_EXT) = SUB<R64W, R64, I64>;

namespace {

template <typename T>
T AddWithCarryNZCV(State &state, T lhs, T rhs, T actual_rhs, T carry) {
  auto unsigned_result = UAdd(UAdd(ZExt(lhs), ZExt(rhs)), ZExt(carry));
  auto signed_result = SAdd(SAdd(SExt(lhs), SExt(rhs)), Signed(ZExt(carry)));
  auto result = TruncTo<T>(unsigned_result);
  FLAG_N = SignFlag(result, lhs, actual_rhs);
  FLAG_Z = ZeroFlag(result, lhs, actual_rhs);
  FLAG_C = UCmpNeq(ZExt(result), unsigned_result);
  FLAG_V = __remill_flag_computation_overflow(
      SCmpNeq(SExt(result), signed_result), lhs, actual_rhs, result);
  return result;
}

template <typename D, typename S1, typename S2>
DEF_SEM(SUBS, D dst, S1 src1, S2 src2) {
  using T = typename BaseType<S2>::BT;
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = AddWithCarryNZCV(state, lhs, UNot(rhs), rhs, T(1));
  WriteZExt(dst, res);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(ADDS, D dst, S1 src1, S2 src2) {
  using T = typename BaseType<S2>::BT;
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = AddWithCarryNZCV(state, lhs, rhs, rhs, T(0));
  WriteZExt(dst, res);
  return memory;
}
}  // namespace

DEF_ISEL(SUBS_32_ADDSUB_SHIFT) = SUBS<R32W, R32, I32>;
DEF_ISEL(SUBS_64_ADDSUB_SHIFT) = SUBS<R64W, R64, I64>;
DEF_ISEL(SUBS_32S_ADDSUB_IMM) = SUBS<R32W, R32, I32>;
DEF_ISEL(SUBS_64S_ADDSUB_IMM) = SUBS<R64W, R64, I64>;
DEF_ISEL(SUBS_32S_ADDSUB_EXT) = SUBS<R32W, R32, I32>;
DEF_ISEL(SUBS_64S_ADDSUB_EXT) = SUBS<R64W, R64, I64>;

DEF_ISEL(ADDS_32_ADDSUB_SHIFT) = ADDS<R32W, R32, I32>;
DEF_ISEL(ADDS_64_ADDSUB_SHIFT) = ADDS<R64W, R64, I64>;
DEF_ISEL(ADDS_32S_ADDSUB_IMM) = ADDS<R32W, R32, I32>;
DEF_ISEL(ADDS_64S_ADDSUB_IMM) = ADDS<R64W, R64, I64>;
DEF_ISEL(ADDS_32S_ADDSUB_EXT) = ADDS<R32W, R32, I32>;
DEF_ISEL(ADDS_64S_ADDSUB_EXT) = ADDS<R64W, R64, I64>;

namespace {

DEF_SEM(UMADDL, R64W dst, R32 src1, R32 src2, R64 src3) {
  Write(dst, UAdd(Read(src3), UMul(ZExt(Read(src1)), ZExt(Read(src2)))));
  return memory;
}

DEF_SEM(SMADDL, R64W dst, R32 src1, R32 src2, R64 src3) {
  auto operand1 = SExt(Signed(Read(src1)));
  auto operand2 = SExt(Signed(Read(src2)));
  auto operand3 = Signed(Read(src3));
  Write(dst, Unsigned(SAdd(operand3, SMul(operand1, operand2))));
  return memory;
}

DEF_SEM(UMULH, R64W dst, R64 src1, R64 src2) {
  uint128_t lhs = ZExt(Read(src1));
  uint128_t rhs = ZExt(Read(src2));
  uint128_t res = UMul(lhs, rhs);
  Write(dst, Trunc(UShr(res, 64)));
  return memory;
}

DEF_SEM(SMULH, R64W dst, R64 src1, R64 src2) {
  int128_t lhs = SExt(Signed(Read(src1)));
  int128_t rhs = SExt(Signed(Read(src2)));
  uint128_t res = Unsigned(SMul(lhs, rhs));
  Write(dst, Trunc(UShr(res, 64)));
  return memory;
}

template <typename D, typename S>
DEF_SEM(UDIV, D dst, S src1, S src2) {
  using T = typename BaseType<S>::BT;
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  if (!rhs) {
    WriteZExt(dst, T(0));
  } else {
    WriteZExt(dst, UDiv(lhs, rhs));
  }
  return memory;
}

template <typename D, typename S>
DEF_SEM(SDIV, D dst, S src1, S src2) {
  using T = typename BaseType<S>::BT;
  auto lhs = Signed(Read(src1));
  auto rhs = Signed(Read(src2));
  if (!rhs) {
    WriteZExt(dst, T(0));
  } else {
    WriteZExt(dst, Unsigned(SDiv(lhs, rhs)));
  }
  return memory;
}

template <typename D, typename S>
DEF_SEM(MADD, D dst, S src1, S src2, S src3) {
  WriteZExt(dst, UAdd(Read(src3), UMul(Read(src1), Read(src2))));
  return memory;
}

template <typename D, typename S>
DEF_SEM(MSUB, D dst, S src1, S src2, S src3) {
  WriteZExt(dst, USub(Read(src3), UMul(Read(src1), Read(src2))));
  return memory;
}

}  // namespace

DEF_ISEL(UMADDL_64WA_DP_3SRC) = UMADDL;
DEF_ISEL(SMADDL_64WA_DP_3SRC) = SMADDL;

DEF_ISEL(UMULH_64_DP_3SRC) = UMULH;
DEF_ISEL(SMULH_64_DP_3SRC) = SMULH;

DEF_ISEL(UDIV_32_DP_2SRC) = UDIV<R32W, R32>;
DEF_ISEL(UDIV_64_DP_2SRC) = UDIV<R64W, R64>;

DEF_ISEL(SDIV_32_DP_2SRC) = SDIV<R32W, R32>;
DEF_ISEL(SDIV_64_DP_2SRC) = SDIV<R64W, R64>;

DEF_ISEL(MADD_32A_DP_3SRC) = MADD<R32W, R32>;
DEF_ISEL(MADD_64A_DP_3SRC) = MADD<R64W, R64>;

DEF_ISEL(MSUB_32A_DP_3SRC) = MSUB<R32W, R32>;
DEF_ISEL(MSUB_64A_DP_3SRC) = MSUB<R64W, R64>;

namespace {

template <typename D, typename S>
DEF_SEM(SBC, D dst, S src1, S src2) {
  auto carry = ZExtTo<S>(Unsigned(FLAG_C));
  WriteZExt(dst, UAdd(UAdd(Read(src1), UNot(Read(src2))), carry));
  return memory;
}

template <typename D, typename S>
DEF_SEM(SBCS, D dst, S src1, S src2) {
  auto carry = ZExtTo<S>(Unsigned(FLAG_C));
  auto res =
      AddWithCarryNZCV(state, Read(src1), UNot(Read(src2)), Read(src2), carry);
  WriteZExt(dst, res);
  return memory;
}

}  // namespace

DEF_ISEL(SBC_32_ADDSUB_CARRY) = SBC<R32W, R32>;
DEF_ISEL(SBC_64_ADDSUB_CARRY) = SBC<R64W, R64>;

DEF_ISEL(SBCS_32_ADDSUB_CARRY) = SBCS<R32W, R32>;
DEF_ISEL(SBCS_64_ADDSUB_CARRY) = SBCS<R64W, R64>;

namespace {

DEF_SEM(FADD_Scalar32, V128W dst, V32 src1, V32 src2) {
  auto val1 = FExtractV32(FReadV32(src1), 0);
  auto val2 = FExtractV32(FReadV32(src2), 0);
  auto sum = CheckedFloatBinOp(state, FAdd32, val1, val2);
  FWriteV32(dst, sum);
  return memory;
}

DEF_SEM(FADD_Scalar64, V128W dst, V64 src1, V64 src2) {
  auto val1 = FExtractV64(FReadV64(src1), 0);
  auto val2 = FExtractV64(FReadV64(src2), 0);
  auto sum = CheckedFloatBinOp(state, FAdd64, val1, val2);
  FWriteV64(dst, sum);
  return memory;
}

DEF_SEM(FSUB_Scalar32, V128W dst, V32 src1, V32 src2) {
  auto val1 = FExtractV32(FReadV32(src1), 0);
  auto val2 = FExtractV32(FReadV32(src2), 0);
  auto sum = CheckedFloatBinOp(state, FSub32, val1, val2);
  FWriteV32(dst, sum);
  return memory;
}

DEF_SEM(FSUB_Scalar64, V128W dst, V64 src1, V64 src2) {
  auto val1 = FExtractV64(FReadV64(src1), 0);
  auto val2 = FExtractV64(FReadV64(src2), 0);
  auto sum = CheckedFloatBinOp(state, FSub64, val1, val2);
  FWriteV64(dst, sum);
  return memory;
}
DEF_SEM(FMUL_Scalar32, V128W dst, V32 src1, V32 src2) {
  auto val1 = FExtractV32(FReadV32(src1), 0);
  auto val2 = FExtractV32(FReadV32(src2), 0);
  auto prod = CheckedFloatBinOp(state, FMul32, val1, val2);
  FWriteV32(dst, prod);
  return memory;
}

DEF_SEM(FMUL_Scalar64, V128W dst, V64 src1, V64 src2) {
  auto val1 = FExtractV64(FReadV64(src1), 0);
  auto val2 = FExtractV64(FReadV64(src2), 0);
  auto prod = CheckedFloatBinOp(state, FMul64, val1, val2);
  FWriteV64(dst, prod);
  return memory;
}

DEF_SEM(FDIV_Scalar32, V128W dst, V32 src1, V32 src2) {
  auto val1 = FExtractV32(FReadV32(src1), 0);
  auto val2 = FExtractV32(FReadV32(src2), 0);
  auto prod = CheckedFloatBinOp(state, FDiv32, val1, val2);
  FWriteV32(dst, prod);
  return memory;
}

DEF_SEM(FMADD_S, V128W dst, V32 src1, V32 src2, V32 src3) {
  auto factor1 = FExtractV32(FReadV32(src1), 0);
  auto factor2 = FExtractV32(FReadV32(src2), 0);
  auto add = FExtractV32(FReadV32(src3), 0);

  auto old_underflow = state.sr.ufc;

  auto zero = __remill_fpu_exception_test_and_clear(0, FE_ALL_EXCEPT);
  BarrierReorder();
  auto prod = FMul32(factor1, factor2);
  BarrierReorder();
  auto except_mul = __remill_fpu_exception_test_and_clear(FE_ALL_EXCEPT, zero);
  BarrierReorder();
  auto res = FAdd32(prod, add);
  BarrierReorder();
  auto except_add =
      __remill_fpu_exception_test_and_clear(FE_ALL_EXCEPT, except_mul);
  SetFPSRStatusFlags(state, except_add);

  // Sets underflow for 0x3fffffff, 0x1 but native doesn't.
  if (state.sr.ufc && !old_underflow) {
    if (IsDenormal(factor1) || IsDenormal(factor2) || IsDenormal(add)) {
      state.sr.ufc = old_underflow;
    }
  }

  FWriteV32(dst, res);
  return memory;
}

DEF_SEM(FMADD_D, V128W dst, V64 src1, V64 src2, V64 src3) {
  auto factor1 = FExtractV64(FReadV64(src1), 0);
  auto factor2 = FExtractV64(FReadV64(src2), 0);
  auto add = FExtractV64(FReadV64(src3), 0);

  auto old_underflow = state.sr.ufc;

  auto zero = __remill_fpu_exception_test_and_clear(0, FE_ALL_EXCEPT);
  BarrierReorder();
  auto prod = FMul64(factor1, factor2);
  BarrierReorder();
  auto except_mul = __remill_fpu_exception_test_and_clear(FE_ALL_EXCEPT, zero);
  BarrierReorder();
  auto res = FAdd64(prod, add);
  BarrierReorder();
  auto except_add =
      __remill_fpu_exception_test_and_clear(FE_ALL_EXCEPT, except_mul);
  SetFPSRStatusFlags(state, except_add);

  // Sets underflow for test case (0x3fffffffffffffff, 0x1) but native doesn't.
  if (state.sr.ufc && !old_underflow) {
    if (IsDenormal(factor1) || IsDenormal(factor2) || IsDenormal(add)) {
      state.sr.ufc = old_underflow;
    }
  }

  FWriteV64(dst, res);
  return memory;
}

DEF_SEM(FDIV_Scalar64, V128W dst, V64 src1, V64 src2) {
  auto val1 = FExtractV64(FReadV64(src1), 0);
  auto val2 = FExtractV64(FReadV64(src2), 0);
  auto prod = CheckedFloatBinOp(state, FDiv64, val1, val2);
  FWriteV64(dst, prod);
  return memory;
}

template <typename S>
void FCompare(State &state, S val1, S val2, bool signal = true) {

  // Set flags for operand == NAN
  if (std::isnan(val1) || std::isnan(val2)) {

    // result = '0011';
    FLAG_N = 0;
    FLAG_Z = 0;
    FLAG_C = 1;
    FLAG_V = 1;

    if (signal) {
      state.sr.ioc = true;
    }

    // Regular float compare
  } else {
    if (FCmpEq(val1, val2)) {

      // result = '0110';
      FLAG_N = 0;
      FLAG_Z = 1;
      FLAG_C = 1;
      FLAG_V = 0;

    } else if (FCmpLt(val1, val2)) {

      // result = '1000';
      FLAG_N = 1;
      FLAG_Z = 0;
      FLAG_C = 0;
      FLAG_V = 0;

    } else {  // FCmpGt(val1, val2)

      // result = '0010';
      FLAG_N = 0;
      FLAG_Z = 0;
      FLAG_C = 1;
      FLAG_V = 0;
    }
  }
}

DEF_SEM(FCMPE_S, V32 src1, V32 src2) {
  auto val1 = FExtractV32(FReadV32(src1), 0);
  auto val2 = FExtractV32(FReadV32(src2), 0);
  FCompare(state, val1, val2);
  return memory;
}

DEF_SEM(FCMPE_SZ, V32 src1) {
  auto val1 = FExtractV32(FReadV32(src1), 0);
  float32_t float_zero = 0.0;
  FCompare(state, val1, float_zero);
  return memory;
}

DEF_SEM(FCMP_S, V32 src1, V32 src2) {
  auto val1 = FExtractV32(FReadV32(src1), 0);
  auto val2 = FExtractV32(FReadV32(src2), 0);
  FCompare(state, val1, val2, false);
  return memory;
}

DEF_SEM(FCMP_SZ, V32 src1) {
  auto val1 = FExtractV32(FReadV32(src1), 0);
  float32_t float_zero = 0.0;
  FCompare(state, val1, float_zero, false);
  return memory;
}

DEF_SEM(FCMPE_D, V64 src1, V64 src2) {
  auto val1 = FExtractV64(FReadV64(src1), 0);
  auto val2 = FExtractV64(FReadV64(src2), 0);
  FCompare(state, val1, val2);
  return memory;
}

DEF_SEM(FCMPE_DZ, V64 src1) {
  auto val1 = FExtractV64(FReadV64(src1), 0);
  float64_t float_zero = 0.0;
  FCompare(state, val1, float_zero);
  return memory;
}

DEF_SEM(FCMP_D, V64 src1, V64 src2) {
  auto val1 = FExtractV64(FReadV64(src1), 0);
  auto val2 = FExtractV64(FReadV64(src2), 0);
  FCompare(state, val1, val2, false);
  return memory;
}

DEF_SEM(FCMP_DZ, V64 src1) {
  auto val1 = FExtractV64(FReadV64(src1), 0);
  float64_t float_zero = 0.0;
  FCompare(state, val1, float_zero, false);
  return memory;
}

DEF_SEM(FABS_S, V128W dst, V32 src) {
  auto val = FExtractV32(FReadV32(src), 0);
  auto result = static_cast<float32_t>(fabs(val));
  FWriteV32(dst, result);
  return memory;
}

DEF_SEM(FABS_D, V128W dst, V64 src) {
  auto val = FExtractV64(FReadV64(src), 0);
  auto result = static_cast<float64_t>(fabs(val));
  FWriteV64(dst, result);
  return memory;
}

DEF_SEM(FNEG_S, V128W dst, V32 src) {
  auto val = FExtractV32(FReadV32(src), 0);
  auto result = -val;
  FWriteV32(dst, result);
  return memory;
}

DEF_SEM(FNEG_D, V128W dst, V64 src) {
  auto val = FExtractV64(FReadV64(src), 0);
  auto result = -val;
  FWriteV64(dst, result);
  return memory;
}

}  // namespace

DEF_ISEL(FSUB_S_FLOATDP2) = FSUB_Scalar32;
DEF_ISEL(FSUB_D_FLOATDP2) = FSUB_Scalar64;

DEF_ISEL(FADD_S_FLOATDP2) = FADD_Scalar32;
DEF_ISEL(FADD_D_FLOATDP2) = FADD_Scalar64;

DEF_ISEL(FMUL_S_FLOATDP2) = FMUL_Scalar32;
DEF_ISEL(FMUL_D_FLOATDP2) = FMUL_Scalar64;

DEF_ISEL(FMADD_S_FLOATDP3) = FMADD_S;
DEF_ISEL(FMADD_D_FLOATDP3) = FMADD_D;

DEF_ISEL(FDIV_S_FLOATDP2) = FDIV_Scalar32;
DEF_ISEL(FDIV_D_FLOATDP2) = FDIV_Scalar64;

DEF_ISEL(FABS_S_FLOATDP1) = FABS_S;
DEF_ISEL(FABS_D_FLOATDP1) = FABS_D;

DEF_ISEL(FNEG_S_FLOATDP1) = FNEG_S;
DEF_ISEL(FNEG_D_FLOATDP1) = FNEG_D;

DEF_ISEL(FCMPE_S_FLOATCMP) = FCMPE_S;
DEF_ISEL(FCMPE_SZ_FLOATCMP) = FCMPE_SZ;
DEF_ISEL(FCMP_S_FLOATCMP) = FCMP_S;
DEF_ISEL(FCMP_SZ_FLOATCMP) = FCMP_SZ;

DEF_ISEL(FCMPE_D_FLOATCMP) = FCMPE_D;
DEF_ISEL(FCMPE_DZ_FLOATCMP) = FCMPE_DZ;
DEF_ISEL(FCMP_D_FLOATCMP) = FCMP_D;
DEF_ISEL(FCMP_DZ_FLOATCMP) = FCMP_DZ;
