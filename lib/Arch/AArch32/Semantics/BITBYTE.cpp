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

namespace {

DEF_COND_SEM(REV, R32W dst, R32 src) {

  auto src = Read(src);

  auto res_31_24 = UShl(src); // result<31:24> = R[m]<7:0>;
  auto res_23_16 = UAnd(UShl(src, uint32_t(8)), uint32_t(255u << 16)); // result<23:16> = R[m]<15:8>;
  auto res_15_8 = UAnd(UShr(src, uint32_t(8)), uint32_t(255u << 8)); // result<15:8>  = R[m]<23:16>;
  auto res_7_0 = UShr(src, uint32_t(24)); // result<7:0>   = R[m]<31:24>;

  auto res = UOr(res_31_24, UOr(res_23_16, UOr(res_15_8, res_7_0)));

  Write(dst, res);
  return memory;

}

}  // namespace

DEF_ISEL(REV) = REV;
