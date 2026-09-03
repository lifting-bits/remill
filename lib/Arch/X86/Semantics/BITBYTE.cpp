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
DEF_ISEL(SETE_MEMb) = SETZ<M8W>;
DEF_ISEL(SETE_GPR8) = SETZ<R8W>;
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
ALWAYS_INLINE static auto BTMemoryIndex(Memory *&memory, S1, S2 src2) {
  using ElementT = typename BaseType<S1>::BT;
  constexpr unsigned kBitIndexShift = sizeof(ElementT) == 8 ? 6u :
                                      sizeof(ElementT) == 4 ? 5u :
                                      sizeof(ElementT) == 2 ? 4u : 3u;
  auto signed_index = SShr(SExtTo<S1>(Read(src2)), SLiteral<S1>(kBitIndexShift));
  return static_cast<addr_t>(signed_index);
}

template <typename S1, typename T>
ALWAYS_INLINE static addr_t BTMemoryIndex(Memory *&, S1, In<T>) {
  return 0;
}

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
  auto index = BTMemoryIndex(memory, src1, src2);
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
  auto index = BTMemoryIndex(memory, src1, src2);
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
  auto index = BTMemoryIndex(memory, src1, src2);
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
  auto index = BTMemoryIndex(memory, src1, src2);
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
DEF_SEM(TZCNT, D dst, S src) {
  auto val = Read(src);
  auto count = CountTrailingZeros(val);
  ClearArithFlags();
  Write(FLAG_ZF, UCmpEq(UAnd(val, 1), 1));
  Write(FLAG_CF, ZeroFlag(val));
  WriteZExt(dst, Select(FLAG_CF, BitSizeOf(src), count));
  return memory;
}

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

template <typename T>
ALWAYS_INLINE static T LowBitMask(T count, T bit_size) {
  if (UCmpEq(count, 0)) {
    return Literal<T>(0);
  }
  if (!UCmpLt(count, bit_size)) {
    return Maximize(Literal<T>(0));
  }
  return USub(UShl(Literal<T>(1), count), Literal<T>(1));
}

template <typename T>
ALWAYS_INLINE static T PopulationCount(T val) {
  auto count = Literal<T>(0);
  for (unsigned i = 0; i < (sizeof(T) * 8U); ++i) {
    count = UAdd(count, UAnd(UShr(val, Literal<T>(i)), Literal<T>(1)));
  }
  return count;
}

ALWAYS_INLINE static uint32_t CRC32Byte(uint32_t crc, uint8_t byte) {
  crc = UXor(crc, ZExtTo<uint32_t>(byte));
  for (unsigned i = 0; i < 8U; ++i) {
    auto low_bit_set = UCmpNeq(UAnd(crc, Literal<uint32_t>(1)), 0U);
    crc = UShr(crc, 1U);
    crc = Select(low_bit_set, UXor(crc, Literal<uint32_t>(0x82F63B78U)), crc);
  }
  return crc;
}

template <typename T>
ALWAYS_INLINE static uint32_t CRC32Value(uint32_t crc, T val) {
  for (unsigned i = 0; i < sizeof(T); ++i) {
    crc = CRC32Byte(crc,
                    TruncTo<uint8_t>(UShr(val, Literal<T>(i * 8U))));
  }
  return crc;
}

template <typename D, typename S1, typename S2>
DEF_SEM(BEXTR, D dst, S1 src1, S2 src2) {
  auto val = Read(src1);
  auto control = Read(src2);
  auto bit_size = BitSizeOf(src1);
  auto start = ZExtTo<S1>(TruncTo<uint8_t>(control));
  auto length =
      ZExtTo<S1>(TruncTo<uint8_t>(UShr(control, Literal<decltype(control)>(8))));
  auto res = Literal<S1>(0);

  if (UCmpLt(start, bit_size) && UCmpNeq(length, 0)) {
    auto avail = USub(bit_size, start);
    auto use_len = Select(UCmpLt(avail, length), avail, length);
    auto mask = LowBitMask(use_len, bit_size);
    res = UAnd(UShr(val, start), mask);
  }

  WriteZExt(dst, res);
  Write(FLAG_CF, false);
  Write(FLAG_OF, false);
  Write(FLAG_ZF, ZeroFlag(res));
  UndefFlag(sf);
  UndefFlag(af);
  UndefFlag(pf);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(BZHI, D dst, S1 src1, S2 src2) {
  auto val = Read(src1);
  auto count = ZExtTo<S1>(TruncTo<uint8_t>(Read(src2)));
  auto bit_size = BitSizeOf(src1);
  auto out_of_range = !UCmpLt(count, bit_size);
  auto mask = LowBitMask(count, bit_size);
  auto res = Select(out_of_range, val, UAnd(val, mask));

  WriteZExt(dst, res);
  Write(FLAG_CF, out_of_range);
  Write(FLAG_OF, false);
  Write(FLAG_ZF, ZeroFlag(res));
  Write(FLAG_SF, SignFlag(res));
  UndefFlag(af);
  UndefFlag(pf);
  return memory;
}

// BMI1 bit-low operations write CF/ZF/SF/OF, leave AF/PF undefined, and do
// not read flags.
template <typename D, typename S>
DEF_SEM(BLSI, D dst, S src) {
  auto val = Read(src);
  auto res = UAnd(val, USub(Literal<S>(0), val));
  WriteZExt(dst, res);
  Write(FLAG_CF, UCmpNeq(val, Literal<S>(0)));
  Write(FLAG_ZF, ZeroFlag(res));
  Write(FLAG_SF, SignFlag(res));
  Write(FLAG_OF, false);
  UndefFlag(af);
  UndefFlag(pf);
  return memory;
}

template <typename D, typename S>
DEF_SEM(BLSR, D dst, S src) {
  auto val = Read(src);
  auto res = UAnd(val, USub(val, Literal<S>(1)));
  WriteZExt(dst, res);
  Write(FLAG_CF, ZeroFlag(val));
  Write(FLAG_ZF, ZeroFlag(res));
  Write(FLAG_SF, SignFlag(res));
  Write(FLAG_OF, false);
  UndefFlag(af);
  UndefFlag(pf);
  return memory;
}

template <typename D, typename S>
DEF_SEM(BLSMSK, D dst, S src) {
  auto val = Read(src);
  auto res = UXor(val, USub(val, Literal<S>(1)));
  WriteZExt(dst, res);
  Write(FLAG_CF, ZeroFlag(val));
  Write(FLAG_ZF, ZeroFlag(res));
  Write(FLAG_SF, SignFlag(res));
  Write(FLAG_OF, false);
  UndefFlag(af);
  UndefFlag(pf);
  return memory;
}

template <typename D, typename S>
DEF_SEM(POPCNT, D dst, S src) {
  auto val = Read(src);
  auto count = PopulationCount(val);
  WriteZExt(dst, count);
  Write(FLAG_CF, false);
  Write(FLAG_PF, false);
  Write(FLAG_AF, false);
  Write(FLAG_ZF, ZeroFlag(val));
  Write(FLAG_SF, false);
  Write(FLAG_OF, false);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PDEP, D dst, S1 src1, S2 src2) {
  auto src = Read(src1);
  auto mask = Read(src2);
  auto res = Literal<S1>(0);
  unsigned src_index = 0;

  for (unsigned i = 0; i < (sizeof(decltype(src)) * 8U); ++i) {
    auto mask_bit = UShl(Literal<S1>(1), Literal<decltype(src)>(i));
    if (UCmpNeq(UAnd(mask, mask_bit), 0)) {
      auto src_bit =
          UAnd(UShr(src, Literal<decltype(src)>(src_index)), Literal<S1>(1));
      if (UCmpNeq(src_bit, 0)) {
        res = UOr(res, mask_bit);
      }
      ++src_index;
    }
  }

  WriteZExt(dst, res);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PEXT, D dst, S1 src1, S2 src2) {
  auto src = Read(src1);
  auto mask = Read(src2);
  auto res = Literal<S1>(0);
  unsigned dst_index = 0;

  for (unsigned i = 0; i < (sizeof(decltype(src)) * 8U); ++i) {
    auto mask_bit = UShl(Literal<S1>(1), Literal<decltype(src)>(i));
    if (UCmpNeq(UAnd(mask, mask_bit), 0)) {
      auto src_bit = UAnd(UShr(src, Literal<decltype(src)>(i)), Literal<S1>(1));
      if (UCmpNeq(src_bit, 0)) {
        res = UOr(res, UShl(Literal<S1>(1), Literal<decltype(src)>(dst_index)));
      }
      ++dst_index;
    }
  }

  WriteZExt(dst, res);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(CRC32, D dst, S1 src1, S2 src2) {
  auto seed = TruncTo<uint32_t>(Read(src1));
  auto val = Read(src2);
  auto crc = CRC32Value(seed, val);
  WriteZExt(dst, crc);
  return memory;
}

}  // namespace

DEF_ISEL(BSWAP_GPRv_16) = BSWAP_16;
DEF_ISEL(BSWAP_GPRv_32) = BSWAP_32;
IF_64BIT(DEF_ISEL(BSWAP_GPRv_64) = BSWAP_64;)

DEF_ISEL_RnW_Mn(TZCNT_GPRv_MEMv, TZCNT);
DEF_ISEL_RnW_Rn(TZCNT_GPRv_GPRv, TZCNT);

DEF_ISEL_RnW_Mn(LZCNT_GPRv_MEMv, LZCNT);
DEF_ISEL_RnW_Rn(LZCNT_GPRv_GPRv, LZCNT);

DEF_ISEL(BEXTR_GPR32d_MEMd_GPR32d) = BEXTR<R32W, M32, R32>;
DEF_ISEL(BEXTR_GPR32d_GPR32d_GPR32d) = BEXTR<R32W, R32, R32>;
DEF_ISEL(BEXTR_VGPR32d_MEMd_VGPR32d) = BEXTR<R32W, M32, R32>;
DEF_ISEL(BEXTR_VGPR32d_VGPR32d_VGPR32d) = BEXTR<R32W, R32, R32>;
IF_64BIT(DEF_ISEL(BEXTR_GPR64q_MEMq_GPR64q) = BEXTR<R64W, M64, R64>;)
IF_64BIT(DEF_ISEL(BEXTR_GPR64q_GPR64q_GPR64q) = BEXTR<R64W, R64, R64>;)
IF_64BIT(DEF_ISEL(BEXTR_VGPR64q_MEMq_VGPR64q) = BEXTR<R64W, M64, R64>;)
IF_64BIT(DEF_ISEL(BEXTR_VGPR64q_VGPR64q_VGPR64q) = BEXTR<R64W, R64, R64>;)

DEF_ISEL(BZHI_GPR32d_MEMd_GPR32d) = BZHI<R32W, M32, R32>;
DEF_ISEL(BZHI_GPR32d_GPR32d_GPR32d) = BZHI<R32W, R32, R32>;
DEF_ISEL(BZHI_VGPR32d_MEMd_VGPR32d) = BZHI<R32W, M32, R32>;
DEF_ISEL(BZHI_VGPR32d_VGPR32d_VGPR32d) = BZHI<R32W, R32, R32>;
IF_64BIT(DEF_ISEL(BZHI_GPR64q_MEMq_GPR64q) = BZHI<R64W, M64, R64>;)
IF_64BIT(DEF_ISEL(BZHI_GPR64q_GPR64q_GPR64q) = BZHI<R64W, R64, R64>;)
IF_64BIT(DEF_ISEL(BZHI_VGPR64q_MEMq_VGPR64q) = BZHI<R64W, M64, R64>;)
IF_64BIT(DEF_ISEL(BZHI_VGPR64q_VGPR64q_VGPR64q) = BZHI<R64W, R64, R64>;)

DEF_ISEL(BLSI_GPR32d_MEMd) = BLSI<R32W, M32>;
DEF_ISEL(BLSI_GPR32d_GPR32d) = BLSI<R32W, R32>;
DEF_ISEL(BLSI_VGPR32d_MEMd) = BLSI<R32W, M32>;
DEF_ISEL(BLSI_VGPR32d_VGPR32d) = BLSI<R32W, R32>;
IF_64BIT(DEF_ISEL(BLSI_GPR64q_MEMq) = BLSI<R64W, M64>;)
IF_64BIT(DEF_ISEL(BLSI_GPR64q_GPR64q) = BLSI<R64W, R64>;)
IF_64BIT(DEF_ISEL(BLSI_VGPR64q_MEMq) = BLSI<R64W, M64>;)
IF_64BIT(DEF_ISEL(BLSI_VGPR64q_VGPR64q) = BLSI<R64W, R64>;)

DEF_ISEL(BLSR_GPR32d_MEMd) = BLSR<R32W, M32>;
DEF_ISEL(BLSR_GPR32d_GPR32d) = BLSR<R32W, R32>;
DEF_ISEL(BLSR_VGPR32d_MEMd) = BLSR<R32W, M32>;
DEF_ISEL(BLSR_VGPR32d_VGPR32d) = BLSR<R32W, R32>;
IF_64BIT(DEF_ISEL(BLSR_GPR64q_MEMq) = BLSR<R64W, M64>;)
IF_64BIT(DEF_ISEL(BLSR_GPR64q_GPR64q) = BLSR<R64W, R64>;)
IF_64BIT(DEF_ISEL(BLSR_VGPR64q_MEMq) = BLSR<R64W, M64>;)
IF_64BIT(DEF_ISEL(BLSR_VGPR64q_VGPR64q) = BLSR<R64W, R64>;)

DEF_ISEL(BLSMSK_GPR32d_MEMd) = BLSMSK<R32W, M32>;
DEF_ISEL(BLSMSK_GPR32d_GPR32d) = BLSMSK<R32W, R32>;
DEF_ISEL(BLSMSK_VGPR32d_MEMd) = BLSMSK<R32W, M32>;
DEF_ISEL(BLSMSK_VGPR32d_VGPR32d) = BLSMSK<R32W, R32>;
IF_64BIT(DEF_ISEL(BLSMSK_GPR64q_MEMq) = BLSMSK<R64W, M64>;)
IF_64BIT(DEF_ISEL(BLSMSK_GPR64q_GPR64q) = BLSMSK<R64W, R64>;)
IF_64BIT(DEF_ISEL(BLSMSK_VGPR64q_MEMq) = BLSMSK<R64W, M64>;)
IF_64BIT(DEF_ISEL(BLSMSK_VGPR64q_VGPR64q) = BLSMSK<R64W, R64>;)

DEF_ISEL_RnW_Mn(POPCNT_GPRv_MEMv, POPCNT);
DEF_ISEL_RnW_Rn(POPCNT_GPRv_GPRv, POPCNT);

DEF_ISEL(PDEP_GPR32d_GPR32d_MEMd) = PDEP<R32W, R32, M32>;
DEF_ISEL(PDEP_GPR32d_GPR32d_GPR32d) = PDEP<R32W, R32, R32>;
DEF_ISEL(PDEP_VGPR32d_VGPR32d_MEMd) = PDEP<R32W, R32, M32>;
DEF_ISEL(PDEP_VGPR32d_VGPR32d_VGPR32d) = PDEP<R32W, R32, R32>;
IF_64BIT(DEF_ISEL(PDEP_GPR64q_GPR64q_MEMq) = PDEP<R64W, R64, M64>;)
IF_64BIT(DEF_ISEL(PDEP_GPR64q_GPR64q_GPR64q) = PDEP<R64W, R64, R64>;)
IF_64BIT(DEF_ISEL(PDEP_VGPR64q_VGPR64q_MEMq) = PDEP<R64W, R64, M64>;)
IF_64BIT(DEF_ISEL(PDEP_VGPR64q_VGPR64q_VGPR64q) = PDEP<R64W, R64, R64>;)

DEF_ISEL(PEXT_GPR32d_GPR32d_MEMd) = PEXT<R32W, R32, M32>;
DEF_ISEL(PEXT_GPR32d_GPR32d_GPR32d) = PEXT<R32W, R32, R32>;
DEF_ISEL(PEXT_VGPR32d_VGPR32d_MEMd) = PEXT<R32W, R32, M32>;
DEF_ISEL(PEXT_VGPR32d_VGPR32d_VGPR32d) = PEXT<R32W, R32, R32>;
IF_64BIT(DEF_ISEL(PEXT_GPR64q_GPR64q_MEMq) = PEXT<R64W, R64, M64>;)
IF_64BIT(DEF_ISEL(PEXT_GPR64q_GPR64q_GPR64q) = PEXT<R64W, R64, R64>;)
IF_64BIT(DEF_ISEL(PEXT_VGPR64q_VGPR64q_MEMq) = PEXT<R64W, R64, M64>;)
IF_64BIT(DEF_ISEL(PEXT_VGPR64q_VGPR64q_VGPR64q) = PEXT<R64W, R64, R64>;)

DEF_ISEL(CRC32_GPRyy_MEMb_32) = CRC32<R32W, R32, M8>;
IF_64BIT(DEF_ISEL(CRC32_GPRyy_MEMb_64) = CRC32<R64W, R64, M8>;)
DEF_ISEL(CRC32_GPRyy_GPR8b_32) = CRC32<R32W, R32, R8>;
IF_64BIT(DEF_ISEL(CRC32_GPRyy_GPR8b_64) = CRC32<R64W, R64, R8>;)
DEF_ISEL(CRC32_GPRyy_MEMv_16) = CRC32<R32W, R32, M16>;
DEF_ISEL(CRC32_GPRyy_MEMv_32) = CRC32<R32W, R32, M32>;
IF_64BIT(DEF_ISEL(CRC32_GPRyy_MEMv_64) = CRC32<R64W, R64, M64>;)
DEF_ISEL(CRC32_GPRyy_GPRv_16) = CRC32<R32W, R32, R16>;
DEF_ISEL(CRC32_GPRyy_GPRv_32) = CRC32<R32W, R32, R32>;
IF_64BIT(DEF_ISEL(CRC32_GPRyy_GPRv_64) = CRC32<R64W, R64, R64>;)

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
