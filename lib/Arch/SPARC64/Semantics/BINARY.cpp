/*
 * Copyright (c) 2019 Trail of Bits, Inc.
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

template <typename Tag, typename T>
ALWAYS_INLINE static void WriteFlagsIncDec(State &state, T lhs, T rhs, T res) {
  FLAG_ICC_ZF = ZeroFlag(res, lhs, rhs);
  FLAG_ICC_NF = SignFlag(res, lhs, rhs);
  FLAG_ICC_VF = Overflow<Tag>::Flag(lhs, rhs, res);
}

template <typename Tag, typename T>
ALWAYS_INLINE static void WriteFlagsAddSub(State &state, T lhs, T rhs, T res) {
  FLAG_ICC_CF = Carry<Tag>::Flag(lhs, rhs, res);
  WriteFlagsIncDec<Tag>(state, lhs, rhs, res);
}

template <typename Tag, typename T>
ALWAYS_INLINE static void WriteXCCFlagsIncDec(State &state, T lhs, T rhs,
                                              T res) {
  FLAG_XCC_ZF = ZeroFlag(res, lhs, rhs);
  FLAG_XCC_NF = SignFlag(res, lhs, rhs);
  FLAG_XCC_VF = Overflow<Tag>::Flag(lhs, rhs, res);
}

template <typename Tag, typename T>
ALWAYS_INLINE static void WriteICCFlagsIncDec(State &state, T lhs, T rhs,
                                              T res) {
  FLAG_ICC_ZF = ZeroFlag(res, lhs, rhs);
  FLAG_ICC_NF = SignFlag(res, lhs, rhs);
  FLAG_ICC_VF = Overflow<Tag>::Flag(lhs, rhs, res);
}

template <typename Tag>
ALWAYS_INLINE static void WriteICCFlagsAddSub(State &state, uint32_t lhs,
                                              uint32_t rhs, uint32_t res) {
  FLAG_ICC_CF = Carry<Tag>::Flag(lhs, rhs, res);
  WriteICCFlagsIncDec<Tag>(state, lhs, rhs, res);
}

template <typename Tag>
ALWAYS_INLINE static void WriteXCCFlagsAddSub(State &state, uint64_t lhs,
                                              uint64_t rhs, uint64_t res) {
  FLAG_XCC_CF = Carry<Tag>::Flag(lhs, rhs, res);
  WriteXCCFlagsIncDec<Tag>(state, lhs, rhs, res);
}

template <typename S1, typename S2, typename D>
DEF_SEM(ADD, S1 src1, S2 src2, D dst) {
  Write(dst, UAdd(Read(src1), Read(src2)));
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(ADDC, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto carry = ZExtTo<S1>(Unsigned(Read(FLAG_ICC_CF)));
  auto sum = UAdd(lhs, rhs);
  auto res = UAdd(sum, carry);
  Write(dst, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(ADDCC, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UAdd(lhs, rhs);
  Write(dst, res);
  WriteICCFlagsAddSub<tag_add>(state, Literal<uint32_t>(lhs),
                               Literal<uint32_t>(rhs), Literal<uint32_t>(res));
  WriteXCCFlagsAddSub<tag_add>(state, lhs, rhs, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(ADDCCC, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto carry = ZExtTo<S1>(Unsigned(Read(FLAG_ICC_CF)));
  auto sum = UAdd(lhs, rhs);
  auto res = UAdd(sum, carry);
  Write(dst, res);
  WriteICCFlagsAddSub<tag_add>(state, static_cast<uint32_t>(lhs),
                               static_cast<uint32_t>(rhs),
                               static_cast<uint32_t>(sum));
  WriteXCCFlagsAddSub<tag_add>(state, lhs, rhs, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(ADDX, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto sum = UAdd(lhs, rhs);
  Write(dst, sum);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(ADDXC, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto carry = ZExtTo<S1>(Unsigned(Read(FLAG_XCC_CF)));
  auto sum = UAdd(lhs, rhs);
  auto res = UAdd(sum, carry);
  Write(dst, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(ADDXCC, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto sum = UAdd(lhs, rhs);
  Write(dst, sum);
  WriteICCFlagsAddSub<tag_add>(state, static_cast<uint32_t>(lhs),
                               static_cast<uint32_t>(rhs),
                               static_cast<uint32_t>(sum));
  WriteXCCFlagsAddSub<tag_add>(state, lhs, rhs, sum);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(ADDXCCC, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto carry = ZExtTo<S1>(Unsigned(Read(FLAG_XCC_CF)));
  auto sum = UAdd(lhs, rhs);
  auto res = UAdd(sum, carry);
  Write(dst, res);
  WriteICCFlagsAddSub<tag_add>(state, static_cast<uint32_t>(lhs),
                               static_cast<uint32_t>(rhs),
                               static_cast<uint32_t>(res));
  WriteXCCFlagsAddSub<tag_add>(state, lhs, rhs, res);
  return memory;
}


template <typename S1, typename S2, typename D>
DEF_SEM(SUB, S1 src1, S2 src2, D dst) {
  Write(dst, USub(Read(src1), Read(src2)));
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(SUBCC, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = USub(lhs, rhs);
  Write(dst, res);
  WriteICCFlagsAddSub<tag_sub>(state, static_cast<uint32_t>(lhs),
                               static_cast<uint32_t>(rhs),
                               static_cast<uint32_t>(res));
  WriteXCCFlagsAddSub<tag_sub>(state, lhs, rhs, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(SUBC, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto carry = ZExtTo<S1>(Unsigned(Read(FLAG_ICC_CF)));
  auto sub = USub(lhs, rhs);
  auto res = USub(sub, carry);
  Write(dst, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(SUBCCC, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto carry = ZExtTo<S1>(Unsigned(Read(FLAG_ICC_CF)));
  auto sub = USub(lhs, rhs);
  auto res = USub(sub, carry);
  WriteZExt(dst, res);
  WriteICCFlagsAddSub<tag_sub>(state, static_cast<uint32_t>(lhs),
                               static_cast<uint32_t>(rhs),
                               static_cast<uint32_t>(res));
  WriteXCCFlagsAddSub<tag_sub>(state, lhs, rhs, res);
  return memory;
}

// TODO(akshay)  revisit tsubcctv semantic
template <typename S1, typename S2, typename D>
DEF_SEM(TADDCC, S1 src1, S2 src2, D dst) {
  auto rs1 = Read(src1);
  auto rs2 = Read(src2);

  // Check for the tag overflow
  auto tag_rs1 = UAnd(rs1, Literal<S1>(0x3));
  auto tag_rs2 = UAnd(rs2, Literal<S2>(0x3));
  auto tag_ov = UCmpNeq(UOr(tag_rs1, tag_rs2), 0);
  auto sum = UAdd(rs1, rs2);
  FLAG_ICC_VF = tag_ov;  //|| Overflow<tag_add>::Flag(rs1, rs2, sum));
  FLAG_ICC_CF = Carry<tag_add>::Flag(static_cast<uint32_t>(rs1),
                                     static_cast<uint32_t>(rs2),
                                     static_cast<uint32_t>(sum));
  FLAG_ICC_ZF = ZeroFlag(static_cast<uint32_t>(sum), src1, src2);
  FLAG_ICC_NF = SignFlag(static_cast<uint32_t>(sum), src1, src2);
  WriteXCCFlagsAddSub<tag_add>(state, rs1, rs2, sum);
  Write(dst, sum);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(TADDCCTV, R8W cond, S1 src1, S2 src2, D dst) {
  auto rs1 = Read(src1);
  auto rs2 = Read(src2);

  // Check for the tag overflow
  auto tag_rs1 = UAnd(rs1, Literal<S1>(0x3));
  auto tag_rs2 = UAnd(rs2, Literal<S2>(0x3));
  auto tag_ov = UCmpNeq(UOr(tag_rs1, tag_rs2), 0);
  if (tag_ov) {
    Write(cond, true);
    HYPER_CALL = AsyncHyperCall::kSPARCTagOverflowAdd;
    HYPER_CALL_VECTOR = 0;
    return memory;
  }

  Write(cond, false);
  auto sum = UAdd(rs1, rs2);
  Write(dst, sum);
  FLAG_ICC_VF = tag_ov;
  FLAG_ICC_CF = Carry<tag_add>::Flag(
      Literal<uint32_t>(rs1), Literal<uint32_t>(rs2), Literal<uint32_t>(sum));
  FLAG_ICC_ZF = ZeroFlag(static_cast<uint32_t>(sum), src1, src2);
  FLAG_ICC_NF = SignFlag(static_cast<uint32_t>(sum), src1, src2);
  WriteXCCFlagsAddSub<tag_add>(state, rs1, rs2, sum);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(TSUBCC, S1 src1, S2 src2, D dst) {
  auto rs1 = Read(src1);
  auto rs2 = Read(src2);

  // Check for the tag overflow
  auto tag_rs1 = UAnd(rs1, Literal<S1>(0x3));
  auto tag_rs2 = UAnd(rs2, Literal<S2>(0x3));
  auto tag_ov = UCmpNeq(UOr(tag_rs1, tag_rs2), 0);
  auto res = USub(rs1, rs2);
  FLAG_ICC_VF = tag_ov;  //|| Overflow<tag_add>::Flag(rs1, rs2, sum));
  FLAG_ICC_CF = Carry<tag_sub>::Flag(static_cast<uint32_t>(rs1),
                                     static_cast<uint32_t>(rs2),
                                     static_cast<uint32_t>(res));
  FLAG_ICC_ZF = ZeroFlag(static_cast<uint32_t>(res), src1, src2);
  FLAG_ICC_NF = SignFlag(static_cast<uint32_t>(res), src1, src2);
  WriteXCCFlagsAddSub<tag_sub>(state, rs1, rs2, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(TSUBCCTV, R8W cond, S1 src1, S2 src2, D dst) {
  auto rs1 = Read(src1);
  auto rs2 = Read(src2);

  // Check for the tag overflow
  auto tag_rs1 = UAnd(rs1, Literal<S1>(0x3));
  auto tag_rs2 = UAnd(rs2, Literal<S2>(0x3));
  auto tag_ov = UCmpNeq(UOr(tag_rs1, tag_rs2), 0);
  if (tag_ov) {
    Write(cond, true);
    HYPER_CALL = AsyncHyperCall::kSPARCTagOverflowSub;
    HYPER_CALL_VECTOR = 0;
    return memory;
  }

  Write(cond, false);

  auto res = USub(rs1, rs2);
  Write(dst, res);
  FLAG_ICC_VF = tag_ov;
  FLAG_ICC_CF = Carry<tag_sub>::Flag(
      Literal<uint32_t>(rs1), Literal<uint32_t>(rs2), Literal<uint32_t>(res));
  FLAG_ICC_ZF = ZeroFlag(Literal<uint32_t>(res), src1, src2);
  FLAG_ICC_NF = SignFlag(Literal<uint32_t>(res), src1, src2);
  WriteXCCFlagsAddSub<tag_sub>(state, rs1, rs2, res);
  return memory;
}

}  // namespace

DEF_ISEL(ADD) = ADD<R64, R64, R64W>;
DEF_ISEL(ADDC) = ADDC<R64, R64, R64W>;
DEF_ISEL(ADDcc) = ADDCC<R64, R64, R64W>;
DEF_ISEL(ADDCcc) = ADDCCC<R64, R64, R64W>;
DEF_ISEL(ADDX) = ADDX<R64, R64, R64W>;
DEF_ISEL(ADDXC) = ADDXC<R64, R64, R64W>;
DEF_ISEL(ADDXcc) = ADDXCC<R64, R64, R64W>;
DEF_ISEL(ADDXCcc) = ADDXCCC<R64, R64, R64W>;

DEF_ISEL(SUB) = SUB<R64, R64, R64W>;
DEF_ISEL(SUBC) = SUBC<R64, R64, R64W>;
DEF_ISEL(SUBcc) = SUBCC<R64, R64, R64W>;
DEF_ISEL(SUBCcc) = SUBCCC<R64, R64, R64W>;
DEF_ISEL(SUBX) = SUB<R64, R64, R64W>;
DEF_ISEL(SUBXcc) = SUBCC<R64, R64, R64W>;

DEF_ISEL(TADDcc) = TADDCC<R64, R64, R64W>;
DEF_ISEL(TADDccTV) = TADDCCTV<R64, R64, R64W>;
DEF_ISEL(TSUBccTV) = TSUBCCTV<R64, R64, R64W>;


namespace {

template <typename S1, typename S2, typename D>
DEF_SEM(SMUL, S1 src1, S2 src2, D dst) {
  auto lhs = Trunc(Signed(Read(src1)));
  auto rhs = Trunc(Signed(Read(src2)));
  auto lhs_wide = SExt(lhs);
  auto rhs_wide = SExt(rhs);
  auto res = SMul(lhs_wide, rhs_wide);
  auto index = Literal<S1>(32);
  auto y_val = UShr(decltype(index)(res), index);
  Write(ASR_Y, y_val);
  WriteSExt(dst, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(SMULCC, S1 src1, S2 src2, D dst) {
  auto lhs = Trunc(Signed(Read(src1)));
  auto rhs = Trunc(Signed(Read(src2)));
  auto lhs_wide = SExt(lhs);
  auto rhs_wide = SExt(rhs);
  auto res = SMul(lhs_wide, rhs_wide);
  FLAG_ICC_NF = SignFlag(static_cast<uint32_t>(res), src1, src2);
  FLAG_ICC_ZF = ZeroFlag(static_cast<uint32_t>(res), src1, src2);
  FLAG_ICC_VF = 0;
  FLAG_ICC_CF = 0;
  FLAG_XCC_NF = SignFlag(static_cast<uint64_t>(res), src1, src2);
  FLAG_XCC_ZF = ZeroFlag(static_cast<uint64_t>(res), src1, src2);
  FLAG_XCC_VF = 0;
  FLAG_XCC_CF = 0;
  auto index = Literal<S1>(32);
  auto y_val = UShr(decltype(index)(res), index);
  Write(ASR_Y, y_val);
  WriteSExt(dst, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(UMUL, S1 src1, S2 src2, D dst) {
  auto lhs = Trunc(Read(src1));
  auto rhs = Trunc(Read(src2));
  auto lhs_wide = ZExt(lhs);
  auto rhs_wide = ZExt(rhs);
  auto res = UMul(lhs_wide, rhs_wide);
  auto index = Literal<S1>(32);
  auto y_val = UShr(decltype(index)(res), index);
  Write(ASR_Y, y_val);
  WriteZExt(dst, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(UMULcc, S1 src1, S2 src2, D dst) {
  auto lhs = Trunc(Read(src1));
  auto rhs = Trunc(Read(src2));
  auto lhs_wide = ZExt(lhs);
  auto rhs_wide = ZExt(rhs);
  auto res = UMul(lhs_wide, rhs_wide);
  FLAG_ICC_NF = SignFlag(static_cast<uint32_t>(res), src1, src2);
  FLAG_ICC_ZF = ZeroFlag(static_cast<uint32_t>(res), src1, src2);
  FLAG_ICC_VF = 0;
  FLAG_ICC_CF = 0;
  FLAG_XCC_NF = SignFlag(static_cast<uint64_t>(res), src1, src2);
  FLAG_XCC_ZF = ZeroFlag(static_cast<uint64_t>(res), src1, src2);
  FLAG_XCC_VF = 0;
  FLAG_XCC_CF = 0;
  auto index = Literal<S1>(32);
  auto y_val = UShr(decltype(index)(res), index);
  Write(ASR_Y, y_val);
  WriteSExt(dst, res);
  return memory;
}


template <typename S1, typename S2, typename D>
DEF_SEM(MULX, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UMul(lhs, rhs);
  Write(dst, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(SDIV, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto lhs_wide = ZExt(lhs);
  auto y = Read(REG_Y);
  auto y_lhs_wide = Signed(
      UOr(decltype(lhs_wide)(UShl(y, Literal<decltype(y)>(32))), lhs_wide));
  auto rhs = Signed(Read(src2));
  auto rhs_wide = SExt(rhs);
  auto quot = SDiv(y_lhs_wide, rhs_wide);
  WriteSExt(dst, quot);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(SDIVCC, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto lhs_wide = ZExt(lhs);
  auto y = Read(REG_Y);
  auto y_lhs_wide = Signed(
      UOr(decltype(lhs_wide)(UShl(y, Literal<decltype(y)>(32))), lhs_wide));
  auto rhs = Read(src2);
  auto rhs_wide = SExt(rhs);
  auto quot = SDiv(y_lhs_wide, rhs_wide);
  FLAG_ICC_NF = SignFlag(static_cast<uint32_t>(quot), src1, src2);
  FLAG_ICC_ZF = ZeroFlag(static_cast<uint32_t>(quot), src1, src2);
  FLAG_ICC_VF = Overflow<tag_sdiv>::Flag(lhs, rhs, quot);
  FLAG_ICC_CF = 0;
  FLAG_XCC_NF = SignFlag(static_cast<uint64_t>(quot), src1, src2);
  FLAG_XCC_ZF = ZeroFlag(static_cast<uint64_t>(quot), src1, src2);
  FLAG_XCC_VF = 0;
  FLAG_XCC_CF = 0;
  auto res = Overflow<tag_sdiv>::Value(lhs, rhs, quot);
  WriteSExt(dst, Trunc(res));
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(UDIV, S1 src1, S2 src2, D dst) {
  auto lhs = Trunc(Read(src1));
  auto rhs = Trunc(Read(src2));
  auto y_reg = Literal<S1>(Read(REG_Y));
  auto shift_y = UShl(y_reg, Literal<decltype(y_reg)>(32));
  auto lhs_wide = UOr(shift_y, ZExt(lhs));
  auto rhs_wide = ZExt(rhs);
  auto quot = UDiv(lhs_wide, rhs_wide);
  auto quot_trunc = Trunc(quot);
  WriteZExt(dst, quot_trunc);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(UDIVCC, S1 src1, S2 src2, D dst) {
  auto lhs = Trunc(Read(src1));
  auto rhs = Trunc(Read(src2));
  auto y_reg = Literal<S1>(Read(REG_Y));
  auto shift_y = UShl(y_reg, Literal<decltype(y_reg)>(32));
  auto lhs_wide = UOr(shift_y, ZExt(lhs));
  auto rhs_wide = ZExt(rhs);
  auto quot = UDiv(lhs_wide, rhs_wide);
  FLAG_ICC_NF = SignFlag(static_cast<uint32_t>(quot), src1, src2);
  FLAG_ICC_ZF = ZeroFlag(static_cast<uint32_t>(quot), src1, src2);
  FLAG_ICC_VF = Overflow<tag_udiv>::Flag(lhs, rhs, quot);
  FLAG_ICC_CF = 0;
  FLAG_XCC_NF = SignFlag(static_cast<uint64_t>(quot), src1, src2);
  FLAG_XCC_ZF = ZeroFlag(static_cast<uint64_t>(quot), src1, src2);
  FLAG_XCC_VF = 0;
  FLAG_XCC_CF = 0;
  auto res = Overflow<tag_udiv>::Value(lhs, rhs, quot);
  WriteZExt(dst, Trunc(res));
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(SDIVX, S1 src1, S2 src2, D dst) {
  auto lhs = Signed(Read(src1));
  auto rhs = Signed(Read(src2));
  auto quot = SDiv(lhs, rhs);
  Write(dst, Unsigned(quot));
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(UDIVX, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto quot = UDiv(lhs, rhs);
  Write(dst, quot);
  return memory;
}

}  // namespace

DEF_ISEL(SMUL) = SMUL<R64, R64, R64W>;
DEF_ISEL(SMULcc) = SMULCC<R64, R64, R64W>;

DEF_ISEL(SDIV) = SDIV<R32, R32, R64W>;
DEF_ISEL(SDIVcc) = SDIVCC<R32, R32, R64W>;

DEF_ISEL(MULX) = MULX<R64, R64, R64W>;
DEF_ISEL(UMUL) = UMUL<R64, R64, R64W>;
DEF_ISEL(UMULcc) = UMULcc<R64, R64, R64W>;

DEF_ISEL(UDIV) = UDIV<R64, R64, R64W>;
DEF_ISEL(UDIVcc) = UDIVCC<R64, R64, R64W>;

DEF_ISEL(UDIVX) = UDIVX<R64, R64, R64W>;
DEF_ISEL(SDIVX) = SDIVX<R64, R64, R64W>;


namespace {

DEF_SEM(MULSCC_R32, R32 src1, R32 src2, R32W dest) {
  auto rs1 = Read(src1);
  auto rs2 = Read(src2);
  auto y = Read(REG_Y);
  auto lsb_y = UAnd(y, Literal<decltype(y)>(0x1));
  auto masked_rs1 = UAnd(rs1, Literal<decltype(rs1)>(0xffffffff));
  auto masked_rs2 = UAnd(rs2, Literal<decltype(rs2)>(0xffffffff));
  auto new_rs2 =
      Select(UCmpEq(lsb_y, 0), Literal<decltype(rs2)>(0), masked_rs2);

  auto flag_nf = Literal<uint32_t>(Read(FLAG_ICC_NF));
  auto flag_vf = Literal<uint32_t>(Read(FLAG_ICC_VF));
  auto nxorv = UXor(flag_nf, flag_vf);
  auto shifted_flag = UShl(nxorv, Literal<decltype(nxorv)>(31));
  auto new_rs1 = UOr(UShr(masked_rs1, Literal<decltype(masked_rs1)>(1)),
                     Literal<decltype(masked_rs1)>(shifted_flag));
  auto res = UAdd(new_rs1, new_rs2);

  // Y register is shifted right by one bit, with the LSB of the unshifted
  // r[rs1] replacing the MSB of Y
  auto shifted_y = UShr(y, Literal<decltype(y)>(1));
  auto lsb_rs1 = UAnd(rs1, Literal<decltype(rs1)>(0x1));
  auto new_y = UOr(shifted_y,
                   decltype(y)(UShl(lsb_rs1, Literal<decltype(lsb_rs1)>(31))));
  Write(REG_Y, new_y);
  Write(dest, res);

  WriteICCFlagsAddSub<tag_add>(state, static_cast<uint32_t>(new_rs1),
                               static_cast<uint32_t>(new_rs2),
                               static_cast<uint32_t>(res));

  // All undefined.
  FLAG_XCC_CF = 0;
  FLAG_XCC_ZF = 0;
  FLAG_XCC_NF = 0;
  FLAG_XCC_VF = 0;


  return memory;
}

}  // namespace

DEF_ISEL(MULScc) = MULSCC_R32;
