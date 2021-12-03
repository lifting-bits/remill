/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 */

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
DEF_SEM(SUB, S1 src1, S2 src2, D dst) {
  Write(dst, USub(Read(src1), Read(src2)));
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(SUBcc, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = USub(lhs, rhs);
  Write(dst, res);
  WriteICCFlagsAddSub<tag_sub>(state, lhs, rhs, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(SUBX, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto carry = ZExtTo<S1>(Unsigned(Read(FLAG_ICC_CF)));
  auto sub = USub(lhs, rhs);
  auto res = USub(sub, carry);
  Write(dst, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(SUBXcc, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto carry = ZExtTo<S1>(Unsigned(Read(FLAG_ICC_CF)));
  auto sub = USub(lhs, rhs);
  auto res = USub(sub, carry);
  WriteZExt(dst, res);
  WriteICCFlagsAddSub<tag_sub>(state, lhs, rhs, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(ADD, S1 src1, S2 src2, D dst) {
  Write(dst, UAdd(Read(src1), Read(src2)));
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(ADDcc, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UAdd(lhs, rhs);
  Write(dst, res);
  WriteICCFlagsAddSub<tag_add>(state, lhs, rhs, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(ADDX, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto carry = ZExtTo<S1>(Unsigned(Read(FLAG_ICC_CF)));
  auto sum = UAdd(lhs, rhs);
  auto res = UAdd(sum, carry);
  Write(dst, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(ADDXcc, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto carry = ZExtTo<S1>(Unsigned(Read(FLAG_ICC_CF)));
  auto sum = UAdd(lhs, rhs);
  auto res = UAdd(sum, carry);
  Write(dst, res);
  WriteICCFlagsAddSub<tag_add>(state, lhs, rhs, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(SMUL, S1 src1, S2 src2, D dst) {
  auto lhs = Signed(Read(src1));
  auto rhs = Signed(Read(src2));
  auto lhs_wide = SExt(lhs);
  auto rhs_wide = SExt(rhs);
  auto res = SMul(lhs_wide, rhs_wide);
  auto res_trunc = TruncTo<S1>(res);
  WriteZExt(dst, res_trunc);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(SMULcc, S1 src1, S2 src2, D dst) {
  auto lhs = Signed(Read(src1));
  auto rhs = Signed(Read(src2));
  auto lhs_wide = SExt(lhs);
  auto rhs_wide = SExt(rhs);
  auto res = SMul(lhs_wide, rhs_wide);
  auto res_trunc = TruncTo<S1>(res);
  FLAG_ICC_NF = SignFlag(static_cast<uint32_t>(res), src1, src2);
  FLAG_ICC_ZF = ZeroFlag(static_cast<uint32_t>(res), src1, src2);
  FLAG_ICC_VF = 0;
  FLAG_ICC_CF = 0;
  auto index = Literal<S1>(32);
  auto y_val = UShr(decltype(index)(res), index);
  Write(ASR_Y, y_val);
  WriteZExt(dst, res_trunc);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(UMUL, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto lhs_wide = ZExt(lhs);
  auto rhs_wide = ZExt(rhs);
  auto res = UMul(lhs_wide, rhs_wide);
  auto res_trunc = TruncTo<S1>(res);
  WriteZExt(dst, res_trunc);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(UMULcc, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto lhs_wide = ZExt(lhs);
  auto rhs_wide = ZExt(rhs);
  auto res = UMul(lhs_wide, rhs_wide);
  auto res_trunc = TruncTo<S1>(res);
  FLAG_ICC_NF = SignFlag(static_cast<uint32_t>(res), src1, src2);
  FLAG_ICC_ZF = ZeroFlag(static_cast<uint32_t>(res), src1, src2);
  FLAG_ICC_VF = 0;
  FLAG_ICC_CF = 0;
  auto index = Literal<S1>(32);
  auto y_val = UShr(decltype(index)(res), index);
  Write(ASR_Y, y_val);
  WriteZExt(dst, res_trunc);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(MULX, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto lhs_wide = ZExt(lhs);
  auto rhs_wide = ZExt(rhs);
  auto res = UMul(lhs_wide, rhs_wide);
  auto res_trunc = TruncTo<S1>(res);
  WriteZExt(dst, res_trunc);
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
  WriteTrunc(dst, quot);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(SDIVcc, S1 src1, S2 src2, D dst) {
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
  auto res = Overflow<tag_sdiv>::Value(lhs, rhs, quot);
  WriteTrunc(dst, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(UDIV, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto lhs_wide = ZExt(lhs);
  auto rhs_wide = ZExt(rhs);
  auto quot = UDiv(lhs_wide, rhs_wide);
  WriteTrunc(dst, quot);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(UDIVcc, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto lhs_wide = ZExt(lhs);
  auto rhs_wide = ZExt(rhs);
  auto quot = UDiv(lhs_wide, rhs_wide);
  FLAG_ICC_NF = SignFlag(static_cast<uint32_t>(quot), src1, src2);
  FLAG_ICC_ZF = ZeroFlag(static_cast<uint32_t>(quot), src1, src2);
  FLAG_ICC_VF = Overflow<tag_udiv>::Flag(lhs, rhs, quot);
  FLAG_ICC_CF = 0;
  auto res = Overflow<tag_udiv>::Value(lhs, rhs, quot);
  WriteTrunc(dst, res);
  return memory;
}

}  // namespace

DEF_ISEL(SUB) = SUB<R32, R32, R32W>;
DEF_ISEL(SUBcc) = SUBcc<R32, R32, R32W>;
DEF_ISEL(SUBX) = SUBX<R32, R32, R32W>;
DEF_ISEL(SUBXcc) = SUBXcc<R32, R32, R32W>;

DEF_ISEL(ADD) = ADD<R32, R32, R32W>;
DEF_ISEL(ADDcc) = ADDcc<R32, R32, R32W>;
DEF_ISEL(ADDX) = ADDX<R32, R32, R32W>;
DEF_ISEL(ADDXcc) = ADDXcc<R32, R32, R32W>;

DEF_ISEL(SMUL) = SMUL<R32, R32, R32W>;
DEF_ISEL(SMULcc) = SMULcc<R32, R32, R32W>;
DEF_ISEL(UMUL) = UMUL<R32, R32, R32W>;
DEF_ISEL(UMULcc) = UMULcc<R32, R32, R32W>;
DEF_ISEL(MULX) = MULX<R32, R32, R32W>;

DEF_ISEL(SDIV) = SDIV<R32, R32, R32W>;
DEF_ISEL(SDIVcc) = SDIVcc<R32, R32, R32W>;
DEF_ISEL(UDIV) = UDIV<R32, R32, R32W>;
DEF_ISEL(UDIVcc) = UDIVcc<R32, R32, R32W>;

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
  return memory;
}

}  // namespace

DEF_ISEL(MULScc) = MULSCC_R32;
