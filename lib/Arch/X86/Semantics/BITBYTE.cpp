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

template <typename D>
DEF_SEM(SETNLE, D dst) {
  Write(dst, BAnd(BNot(FLAG_ZF), BXnor(FLAG_SF, FLAG_OF)));
  return memory;
}

template <typename D>
DEF_SEM(SETNS, D dst) {
  Write(dst, BNot(FLAG_SF));
  return memory;
}

template <typename D>
DEF_SEM(SETL, D dst) {
  Write(dst, BXor(FLAG_SF, FLAG_OF));
  return memory;
}

template <typename D>
DEF_SEM(SETNP, D dst) {
  Write(dst, BNot(FLAG_PF));
  return memory;
}

template <typename D>
DEF_SEM(SETNZ, D dst) {
  Write(dst, BNot(FLAG_ZF));
  return memory;
}

template <typename D>
DEF_SEM(SETNB, D dst) {
  Write(dst, BNot(FLAG_CF));
  return memory;
}

template <typename D>
DEF_SEM(SETNO, D dst) {
  Write(dst, BNot(FLAG_OF));
  return memory;
}

template <typename D>
DEF_SEM(SETNL, D dst) {
  Write(dst, BXnor(FLAG_SF, FLAG_OF));
  return memory;
}

template <typename D>
DEF_SEM(SETNBE, D dst) {
  Write(dst, BAnd(BNot(FLAG_CF), BNot(FLAG_ZF)));
  return memory;
}

template <typename D>
DEF_SEM(SETBE, D dst) {
  Write(dst, BOr(FLAG_CF, FLAG_ZF));
  return memory;
}

template <typename D>
DEF_SEM(SETZ, D dst) {
  Write(dst, FLAG_ZF);
  return memory;
}

template <typename D>
DEF_SEM(SETP, D dst) {
  Write(dst, FLAG_PF);
  return memory;
}

template <typename D>
DEF_SEM(SETS, D dst) {
  Write(dst, FLAG_SF);
  return memory;
}

template <typename D>
DEF_SEM(SETO, D dst) {
  Write(dst, FLAG_OF);
  return memory;
}

template <typename D>
DEF_SEM(SETB, D dst) {
  Write(dst, FLAG_CF);
  return memory;
}

template <typename D>
DEF_SEM(SETLE, D dst) {
  Write(dst, BOr(FLAG_ZF, BXor(FLAG_SF, FLAG_OF)));
  return memory;
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


#define _BTClearUndefFlags() \
  do { \
    UndefFlag(of); \
    UndefFlag(sf); \
    UndefFlag(zf); \
    UndefFlag(af); \
    UndefFlag(pf); \
  } while (false)

template <typename S1, typename S2>
DEF_SEM(BTreg, S1 src1, S2 src2) {
  auto val = Read(src1);
  auto bit = ZExtTo<S1>(Read(src2));
  auto bit_mask = UShl(Literal<S1>(1), URem(bit, BitSizeOf(src1)));
  Write(FLAG_CF, UCmpNeq(UAnd(val, bit_mask), Literal<S1>(0)));
  _BTClearUndefFlags();
  return memory;
}

template <typename S1, typename S2>
DEF_SEM(BTmem, S1 src1, S2 src2) {
  auto bit = ZExtTo<S1>(Read(src2));
  auto bit_mask = UShl(Literal<S1>(1), URem(bit, BitSizeOf(src1)));
  auto index = UDiv(bit, BitSizeOf(src1));
  auto val = Read(GetElementPtr(src1, index));
  Write(FLAG_CF, UCmpNeq(UAnd(val, bit_mask), Literal<S1>(0)));
  _BTClearUndefFlags();
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(BTSreg, D dst, S1 src1, S2 src2) {
  auto val = Read(src1);
  auto bit = ZExtTo<S1>(Read(src2));
  auto bit_mask = UShl(Literal<S1>(1), URem(bit, BitSizeOf(val)));
  WriteZExt(dst, UOr(val, bit_mask));
  Write(FLAG_CF, UCmpNeq(UAnd(val, bit_mask), Literal<S1>(0)));
  _BTClearUndefFlags();
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(BTSmem, D dst, S1 src1, S2 src2) {
  auto bit = ZExtTo<S1>(Read(src2));
  auto bit_mask = UShl(Literal<S1>(1), URem(bit, BitSizeOf(src1)));
  auto index = UDiv(bit, BitSizeOf(src1));
  auto val = Read(GetElementPtr(src1, index));
  Write(GetElementPtr(dst, index), UOr(val, bit_mask));
  Write(FLAG_CF, UCmpNeq(UAnd(val, bit_mask), Literal<S1>(0)));
  _BTClearUndefFlags();
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(BTRreg, D dst, S1 src1, S2 src2) {
  auto val = Read(src1);
  auto bit = ZExtTo<S1>(Read(src2));
  auto bit_mask = UShl(Literal<S1>(1), URem(bit, BitSizeOf(src1)));
  WriteZExt(dst, UAnd(val, UNot(bit_mask)));
  Write(FLAG_CF, UCmpNeq(UAnd(val, bit_mask), Literal<S1>(0)));
  _BTClearUndefFlags();
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(BTRmem, D dst, S1 src1, S2 src2) {
  auto bit = ZExtTo<S1>(Read(src2));
  auto bit_mask = UShl(Literal<S1>(1), URem(bit, BitSizeOf(src1)));
  auto index = UDiv(bit, BitSizeOf(src1));
  auto val = Read(GetElementPtr(src1, index));
  Write(GetElementPtr(dst, index), UAnd(val, UNot(bit_mask)));
  Write(FLAG_CF, UCmpNeq(UAnd(val, bit_mask), Literal<S1>(0)));
  _BTClearUndefFlags();
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(BTCreg, D dst, S1 src1, S2 src2) {
  auto val = Read(src1);
  auto bit = ZExtTo<S1>(Read(src2));
  auto bit_mask = UShl(Literal<S1>(1), URem(bit, BitSizeOf(val)));
  WriteZExt(dst, UXor(val, bit_mask));
  Write(FLAG_CF, UCmpNeq(UAnd(val, bit_mask), Literal<S1>(0)));
  _BTClearUndefFlags();
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(BTCmem, D dst, S1 src1, S2 src2) {
  auto bit = ZExtTo<S1>(Read(src2));
  auto bit_mask = UShl(Literal<S1>(1), URem(bit, BitSizeOf(src1)));
  auto index = UDiv(bit, BitSizeOf(src1));
  auto val = Read(GetElementPtr(src1, index));
  Write(GetElementPtr(dst, index), UXor(val, bit_mask));
  Write(FLAG_CF, UCmpNeq(UAnd(val, bit_mask), Literal<S1>(0)));
  _BTClearUndefFlags();
  return memory;
}

#undef _BTClearUndefFlags

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

namespace {
DEF_SEM(BSWAP_16, R16W dst, R16 src) {
  Write(dst, static_cast<uint16_t>(0));
  return memory;
}

DEF_SEM(BSWAP_32, R32W dst, R32 src) {

  //  auto val = Read(src);
  //  auto d = UAnd(val, 0xff);
  //  auto c = UAnd(UShr(val, 8), 0xff);
  //  auto b = UAnd(UShr(val, 16), 0xff);
  //  auto a = UAnd(UShr(val, 24), 0xff);
  //  auto new_a = UShl(d, 24);
  //  auto new_b = UShl(c, 16);
  //  auto new_c = UShl(b, 8);
  //  auto new_d = a;
  //  WriteZExt(dst, UOr(UOr(new_a, new_b), UOr(new_c, new_d)));
  WriteZExt(dst, __builtin_bswap32(Read(src)));
  return memory;
}

#if 64 == ADDRESS_SIZE_BITS
DEF_SEM(BSWAP_64, R64W dst, R64 src) {
  Write(dst, __builtin_bswap64(Read(src)));
  return memory;
}
#endif  // 64 == ADDRESS_SIZE_BITS

template <typename D, typename S>
DEF_SEM(LZCNT, D dst, S src) {
  auto val = Read(src);
  auto count = CountLeadingZeros(val);
  ClearArithFlags();
  Write(FLAG_ZF, SignFlag(val));
  Write(FLAG_CF, UCmpEq(val, 0));
  WriteZExt(dst, Select(FLAG_CF, BitSizeOf(src), count));
  return memory;
}

}  // namespace

DEF_ISEL(BSWAP_GPRv_16) = BSWAP_16;
DEF_ISEL(BSWAP_GPRv_32) = BSWAP_32;
IF_64BIT(DEF_ISEL(BSWAP_GPRv_64) = BSWAP_64;)

DEF_ISEL_RnW_Mn(LZCNT_GPRv_MEMv, LZCNT);
DEF_ISEL_RnW_Rn(LZCNT_GPRv_GPRv, LZCNT);

namespace {
template <typename D, typename S>
DEF_SEM(BSR, D dst, S src) {
  auto val = Read(src);
  auto count = CountLeadingZeros(val);
  auto index = USub(USub(BitSizeOf(src), count), Literal<S>(1));
  Write(FLAG_ZF, ZeroFlag(val));
  auto index_ret = Select(FLAG_ZF, Read(dst), ZExtTo<D>(index));
  Write(FLAG_OF, BUndefined());  // Undefined, but experimentally 0.
  Write(FLAG_SF, BUndefined());  // Undefined, but experimentally 0.
  Write(FLAG_PF, ParityFlag(index));  // Undefined, but experimentally 1.
  Write(FLAG_AF, BUndefined());  // Undefined, but experimentally 0.
  Write(FLAG_CF, BUndefined());  // Undefined, but experimentally 0.
  Write(dst, index_ret);
  return memory;
}

template <typename D, typename S>
DEF_SEM(BSF, D dst, S src) {
  auto val = Read(src);
  Write(FLAG_ZF, ZeroFlag(val));
  auto index = Select(FLAG_ZF, Read(dst), ZExtTo<D>(CountTrailingZeros(val)));
  Write(FLAG_OF, BUndefined());  // Undefined, but experimentally 0.
  Write(FLAG_SF, BUndefined());  // Undefined, but experimentally 0.
  Write(FLAG_PF, ParityFlag(index));
  Write(FLAG_AF, BUndefined());  // Undefined, but experimentally 0.
  Write(FLAG_CF, BUndefined());  // Undefined, but experimentally 0.
  Write(dst, index);
  return memory;
}

}  // namespace

DEF_ISEL_RnW_Mn(BSR_GPRv_MEMv, BSR);
DEF_ISEL_RnW_Rn(BSR_GPRv_GPRv, BSR);

DEF_ISEL_RnW_Mn(BSF_GPRv_MEMv, BSF);
DEF_ISEL_RnW_Rn(BSF_GPRv_GPRv, BSF);
