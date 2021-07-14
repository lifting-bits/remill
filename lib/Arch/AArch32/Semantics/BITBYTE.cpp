/*
 * Copyright (c) 2020 Trail of Bits, Inc.
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
DEF_COND_SEM(CLZ, R32W dst, R32 src) {
  auto count = CountLeadingZeros(Read(src));
  WriteZExt(dst, count);
  return memory;
}
}  // namespace

DEF_ISEL(CLZ) = CLZ;

// Bitfield Insert
namespace {
DEF_COND_SEM(BFI, R32W dst, R32 src1, R32 src2, I32 msb, I32 lsb) {
  auto rd = Read(src1);
  auto rn = Read(src2);
  auto msbit = Read(msb);
  auto lsbit = Read(lsb);

  auto width = msbit - lsbit + 1;
  auto mask = uint32_t((1 << width) - 1);

  auto res = UOr(rd, UShl(UAnd(rn, mask), lsbit));

  Write(dst, res);
  return memory;
}

DEF_COND_SEM(BFC, R32W dst, R32 src1, I32 msb, I32 lsb) {
  auto rd = Read(src1);
  auto msbit = Read(msb);
  auto lsbit = Read(lsb);

  auto width = msbit - lsbit + 1;
  auto mask = uint32_t(((1 << width) - 1) << (lsbit + 1));

  auto res = UAnd(rd, UNot(mask));

  Write(dst, res);
  return memory;
}
}  // namespace

DEF_ISEL(BFI) = BFI;
DEF_ISEL(BFC) = BFC;


// Bitfield Extract
namespace {
DEF_COND_SEM(SBFX, R32W dst, R32 src1, I32 src2, I32 src3) {
  auto src = Signed(Read(src1));
  auto lsbit = Read(src2);
  auto widthminus1 = Read(src3);
  auto msbit = Signed(lsbit + widthminus1);

  // Extract <msbit:lsbit> and retain high bit sign of msbit
  // Shift lift to remove the high bits, then shift right to remove the low bits
  auto res = SShr(SShl(src, int32_t(31) - Signed(msbit)),
                  int32_t(31) - Signed(widthminus1));
  Write(dst, Unsigned(res));
  return memory;
}

DEF_COND_SEM(UBFX, R32W dst, R32 src1, I32 src2, I32 src3) {
  auto src = Read(src1);
  auto lsbit = Read(src2);
  auto widthminus1 = Read(src3);
  auto msbit = lsbit + widthminus1;

  // Extract <msbit:lsbit> unsigned
  // Shift lift to remove the high bits, then shift right to remove the low bits
  auto res = UShr(UShl(src, uint32_t(31) - msbit), uint32_t(31) - widthminus1);
  Write(dst, res);
  return memory;
}
}  // namespace

DEF_ISEL(SBFX) = SBFX;
DEF_ISEL(UBFX) = UBFX;


// Reverse Bit/Byte
namespace {
DEF_COND_SEM(REV, R32W dst, R32 src1) {
  auto src = Read(src1);

  auto res_31_24 = UShl(src, uint32_t(24u));  // result<31:24> = R[m]<7:0>;
  auto res_23_16 = UAnd(UShl(src, uint32_t(8u)),
                        uint32_t(255u << 16u));  // result<23:16> = R[m]<15:8>;
  auto res_15_8 = UAnd(UShr(src, uint32_t(8u)),
                       uint32_t(255u << 8u));  // result<15:8>  = R[m]<23:16>;
  auto res_7_0 = UShr(src, uint32_t(24));  // result<7:0>   = R[m]<31:24>;

  auto res = UOr(res_31_24, UOr(res_23_16, UOr(res_15_8, res_7_0)));

  Write(dst, res);
  return memory;
}

DEF_COND_SEM(REV16, R32W dst, R32 src1) {
  auto src = Read(src1);

  auto res_31_24 = UAnd(UShl(src, uint32_t(8u)),
                        uint32_t(255u << 24u));  // result<31:24> = R[m]<23:16>;
  auto res_23_16 = UAnd(UShr(src, uint32_t(8u)),
                        uint32_t(255u << 16u));  // result<23:16> = R[m]<31:24>;
  auto res_15_8 = UAnd(UShl(src, uint32_t(8u)),
                       uint32_t(255u << 8u));  // result<15:8>  = R[m]<7:0>;
  auto res_7_0 = UAnd(UShr(src, uint32_t(8u)),
                      uint32_t(255u));  // result<7:0>   = R[m]<15:8>;

  auto res = UOr(res_31_24, UOr(res_23_16, UOr(res_15_8, res_7_0)));

  Write(dst, res);
  return memory;
}

template <typename T, size_t n>
ALWAYS_INLINE static T ReverseBits(T v) {
  T rv = 0;
  _Pragma("unroll") for (size_t i = 0; i < n; ++i, v >>= 1) {
    rv = (rv << T(1)) | (v & T(1));
  }
  return rv;
}

#if !__has_builtin(__builtin_bitreverse32)
#  define __builtin_bitreverse32(x) ReverseBits<uint32_t, 32>(x)
#endif

DEF_COND_SEM(RBIT, R32W dst, R32 src) {
  WriteZExt(dst, __builtin_bitreverse32(Read(src)));
  return memory;
}

DEF_COND_SEM(REVSH, R32W dst, R32 src1) {
  auto src = Trunc(Read(src1));

  auto result_31_8 =
      Unsigned(SExt(UShl(src, uint16_t(8u))));  //SignExtend(R[m]<7:0>, 24);
  auto result_7_0 = ZExt(UShr(Unsigned(src), uint16_t(8u)));  //R[m]<15:8>;

  auto res = UOr(result_31_8, result_7_0);

  Write(dst, res);
  return memory;
}
}  // namespace

DEF_ISEL(REV) = REV;
DEF_ISEL(REV16) = REV16;
DEF_ISEL(RBIT) = RBIT;
DEF_ISEL(REVSH) = REVSH;
