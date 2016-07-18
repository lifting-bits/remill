/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_X86_SEMANTICS_BITBYTE_H_
#define REMILL_ARCH_X86_SEMANTICS_BITBYTE_H_

namespace {

template <typename D>
DEF_SEM(SETNLE, D dst) {
  Write(dst, BAnd(BNot(FLAG_ZF), BXnor(FLAG_CF, FLAG_PF)));
}

template <typename D>
DEF_SEM(SETNS, D dst) {
  Write(dst, BNot(FLAG_SF));
}

template <typename D>
DEF_SEM(SETL, D dst) {
  Write(dst, BXor(FLAG_SF, FLAG_OF));
}

template <typename D>
DEF_SEM(SETNP, D dst) {
  Write(dst, BNot(FLAG_PF));
}

template <typename D>
DEF_SEM(SETNZ, D dst) {
  Write(dst, BNot(FLAG_ZF));
}

template <typename D>
DEF_SEM(SETNB, D dst) {
  Write(dst, BNot(FLAG_CF));
}

template <typename D>
DEF_SEM(SETNO, D dst) {
  Write(dst, BNot(FLAG_OF));
}

template <typename D>
DEF_SEM(SETNL, D dst) {
  Write(dst, BXnor(FLAG_SF, FLAG_OF));
}

template <typename D>
DEF_SEM(SETNBE, D dst) {
  Write(dst, BNot(BOr(FLAG_DF, FLAG_ZF)));
}

template <typename D>
DEF_SEM(SETBE, D dst) {
  Write(dst, BOr(FLAG_CF, FLAG_ZF));
}

template <typename D>
DEF_SEM(SETZ, D dst) {
  Write(dst, FLAG_ZF);
}

template <typename D>
DEF_SEM(SETP, D dst) {
  Write(dst, FLAG_PF);
}

template <typename D>
DEF_SEM(SETS, D dst) {
  Write(dst, FLAG_SF);
}

template <typename D>
DEF_SEM(SETO, D dst) {
  Write(dst, FLAG_OF);
}

template <typename D>
DEF_SEM(SETB, D dst) {
  Write(dst, FLAG_CF);
}

template <typename D>
DEF_SEM(SETLE, D dst) {
  Write(dst, BOr(FLAG_ZF, BXor(FLAG_SF, FLAG_OF)));
}

}  // namespace
DEF_ISEL(SETB_MEMb) = SETB<M8W>;
DEF_ISEL(SETB_GPR8) = SETB<R8W>;
DEF_ISEL(SETL_MEMb) = SETL<M8W>;
DEF_ISEL(SETL_GPR8) = SETL<R8W>;
DEF_ISEL(SETO_MEMb) = SETO<M8W>;
DEF_ISEL(SETO_GPR8) = SETO<R8W>;
DEF_ISEL(SETP_MEMb) = SETP<M8W>;
DEF_ISEL(SETP_GPR8) = SETP<R8W>;
DEF_ISEL(SETZ_MEMb) = SETZ<M8W>;
DEF_ISEL(SETZ_GPR8) = SETZ<R8W>;
DEF_ISEL(SETS_MEMb) = SETS<M8W>;
DEF_ISEL(SETS_GPR8) = SETS<R8W>;
DEF_ISEL(SETNO_MEMb) = SETNO<M8W>;
DEF_ISEL(SETNO_GPR8) = SETNO<R8W>;
DEF_ISEL(SETNL_MEMb) = SETNL<M8W>;
DEF_ISEL(SETNL_GPR8) = SETNL<R8W>;
DEF_ISEL(SETNB_MEMb) = SETNB<M8W>;
DEF_ISEL(SETNB_GPR8) = SETNB<R8W>;
DEF_ISEL(SETNZ_MEMb) = SETNZ<M8W>;
DEF_ISEL(SETNZ_GPR8) = SETNZ<R8W>;
DEF_ISEL(SETNS_MEMb) = SETNS<M8W>;
DEF_ISEL(SETNS_GPR8) = SETNS<R8W>;
DEF_ISEL(SETNP_MEMb) = SETNP<M8W>;
DEF_ISEL(SETNP_GPR8) = SETNP<R8W>;
DEF_ISEL(SETNBE_MEMb) = SETNBE<M8W>;
DEF_ISEL(SETNBE_GPR8) = SETNBE<R8W>;
DEF_ISEL(SETLE_MEMb) = SETLE<M8W>;
DEF_ISEL(SETLE_GPR8) = SETLE<R8W>;
DEF_ISEL(SETNLE_MEMb) = SETNLE<M8W>;
DEF_ISEL(SETNLE_GPR8) = SETNLE<R8W>;
DEF_ISEL(SETBE_MEMb) = SETBE<M8W>;
DEF_ISEL(SETBE_GPR8) = SETBE<R8W>;

namespace {

template <typename S1, typename S2>
DEF_SEM(BTreg, S1 src1, S2 src2) {
  auto val = Read(src1);
  auto bit = ZExtTo<S1>(Read(src2));
  auto bit_mask = UShl(Literal<S1>(1), URem(bit, BitSizeOf(src1)));
  Write(FLAG_CF, UCmpNeq(UAnd(val, bit_mask), Literal<S1>(0)));
}

template <typename S1, typename S2>
DEF_SEM(BTmem, S1 src1, S2 src2) {
  auto bit = ZExtTo<S1>(Read(src2));
  auto bit_mask = UShl(Literal<S1>(1), URem(bit, BitSizeOf(src1)));
  auto index = UDiv(bit, BitSizeOf(src1));
  auto val = Read(GetElementPtr(src1, index));
  Write(FLAG_CF, UCmpNeq(UAnd(val, bit_mask), Literal<S1>(0)));
}

template <typename D, typename S1, typename S2>
DEF_SEM(BTSreg, D dst, S1 src1, S2 src2) {
  auto val = Read(src1);
  auto bit = ZExtTo<S1>(Read(src2));
  auto bit_mask = UShl(Literal<S1>(1), URem(bit, BitSizeOf(val)));
  WriteZExt(dst, UOr(val, bit_mask));
  Write(FLAG_CF, UCmpNeq(UAnd(val, bit_mask), Literal<S1>(0)));
}

template <typename D, typename S1, typename S2>
DEF_SEM(BTSmem, D dst, S1 src1, S2 src2) {
  auto bit = ZExtTo<S1>(Read(src2));
  auto bit_mask = UShl(Literal<S1>(1), URem(bit, BitSizeOf(src1)));
  auto index = UDiv(bit, BitSizeOf(src1));
  auto val = Read(GetElementPtr(src1, index));
  Write(GetElementPtr(dst, index), UOr(val, bit_mask));
  Write(FLAG_CF, UCmpNeq(UAnd(val, bit_mask), Literal<S1>(0)));
}

template <typename D, typename S1, typename S2>
DEF_SEM(BTRreg, D dst, S1 src1, S2 src2) {
  auto val = Read(src1);
  auto bit = ZExtTo<S1>(Read(src2));
  auto bit_mask = UShl(Literal<S1>(1), URem(bit, BitSizeOf(src1)));
  WriteZExt(dst, UAnd(val, UNot(bit_mask)));
  Write(FLAG_CF, UCmpNeq(UAnd(val, bit_mask), Literal<S1>(0)));
}

template <typename D, typename S1, typename S2>
DEF_SEM(BTRmem, D dst, S1 src1, S2 src2) {
  auto bit = ZExtTo<S1>(Read(src2));
  auto bit_mask = UShl(Literal<S1>(1), URem(bit, BitSizeOf(src1)));
  auto index = UDiv(bit, BitSizeOf(src1));
  auto val = Read(GetElementPtr(src1, index));
  Write(GetElementPtr(dst, index), UAnd(val, UNot(bit_mask)));
  Write(FLAG_CF, UCmpNeq(UAnd(val, bit_mask), Literal<S1>(0)));
}

template <typename D, typename S1, typename S2>
DEF_SEM(BTCreg, D dst, S1 src1, S2 src2) {
  auto val = Read(src1);
  auto bit = ZExtTo<S1>(Read(src2));
  auto bit_mask = UShl(Literal<S1>(1), URem(bit, BitSizeOf(val)));
  WriteZExt(dst, UXor(val, bit_mask));
  Write(FLAG_CF, UCmpNeq(UAnd(val, bit_mask), Literal<S1>(0)));
}

template <typename D, typename S1, typename S2>
DEF_SEM(BTCmem, D dst, S1 src1, S2 src2) {
  auto bit = ZExtTo<S1>(Read(src2));
  auto bit_mask = UShl(Literal<S1>(1), URem(bit, BitSizeOf(src1)));
  auto index = UDiv(bit, BitSizeOf(src1));
  auto val = Read(GetElementPtr(src1, index));
  Write(GetElementPtr(dst, index), UXor(val, bit_mask));
  Write(FLAG_CF, UCmpNeq(UAnd(val, bit_mask), Literal<S1>(0)));
}

}  // namespace

DEF_ISEL_Mn_In(BT_MEMv_IMMb, BTmem);
DEF_ISEL_Rn_In(BT_GPRv_IMMb, BTreg);
DEF_ISEL_Mn_Rn(BT_MEMv_GPRv, BTmem);
DEF_ISEL_Rn_Rn(BT_GPRv_GPRv, BTreg);

DEF_ISEL_MnW_Mn_In(BTS_MEMv_IMMb, BTSmem);
DEF_ISEL_RnW_Rn_In(BTS_GPRv_IMMb, BTSreg);
DEF_ISEL_MnW_Mn_Rn(BTS_MEMv_GPRv, BTSmem);
DEF_ISEL_RnW_Rn_Rn(BTS_GPRv_GPRv, BTSreg);

DEF_ISEL_MnW_Mn_In(BTR_MEMv_IMMb, BTRmem);
DEF_ISEL_RnW_Rn_In(BTR_GPRv_IMMb, BTRreg);
DEF_ISEL_MnW_Mn_Rn(BTR_MEMv_GPRv, BTRmem);
DEF_ISEL_RnW_Rn_Rn(BTR_GPRv_GPRv, BTRreg);

DEF_ISEL_MnW_Mn_In(BTC_MEMv_IMMb, BTCmem);
DEF_ISEL_RnW_Rn_In(BTC_GPRv_IMMb, BTCreg);
DEF_ISEL_MnW_Mn_Rn(BTC_MEMv_GPRv, BTCmem);
DEF_ISEL_RnW_Rn_Rn(BTC_GPRv_GPRv, BTCreg);

#endif  // REMILL_ARCH_X86_SEMANTICS_BITBYTE_H_
