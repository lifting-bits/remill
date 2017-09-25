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

// The post-decoder handles the rotation of the register using a `ShiftReg`
// operand for `src1`, and combines the `wmask` and `tmask` into a single
// `mask`.
template <typename D, typename S1, typename S2>
DEF_SEM(UBFM, D dst, S1 src1, S2 mask) {
  WriteZExt(dst, UAnd(Read(src1), Read(mask)));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(SBFM, D dst, S1 src1, S2 src2, S2 src3, S2 src4, S2 src5) {
  using T = typename BaseType<S2>::BT;
  auto src = Read(src1);
  auto R = Read(src2);
  auto S = Read(src3);
  auto wmask = Read(src4);
  auto tmask = Read(src5);

  // Perform bitfield move on low bits.
  auto bot = UAnd(Ror(src, R), wmask);

  // Determine extension bits (sign, zero or dest register).
  constexpr auto shift_max = T(sizeof(T) * 8 - 1);
  auto top = Unsigned(SShr(Signed(UShl(src, USub(shift_max, S))), shift_max));

  // Combine extension bits and result bits.
  WriteZExt(dst, UOr(UAnd(top, UNot(tmask)), UAnd(bot, tmask)));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(BFM, D dst, S1 src1, S2 src2, S2 src3, S2 src4) {
  using T = typename BaseType<S2>::BT;
  auto dst_val = TruncTo<T>(Read(dst));  // May be wider due to zero-extension.
  auto src = Read(src1);
  auto R = Read(src2);
  auto wmask = Read(src3);
  auto tmask = Read(src4);

  // Perform bitfield move on low bits.
  auto bot = UOr(UAnd(dst_val, UNot(wmask)), UAnd(Ror(src, R), wmask));

  // Combine extension bits and result bits.
  WriteZExt(dst, UOr(UAnd(dst_val, UNot(tmask)), UAnd(bot, tmask)));
  return memory;
}

}  // namespace

DEF_ISEL(UBFM_32M_BITFIELD) = UBFM<R32W, R32, I32>;
DEF_ISEL(UBFM_64M_BITFIELD) = UBFM<R64W, R64, I64>;

DEF_ISEL(SBFM_32M_BITFIELD) = SBFM<R32W, R32, I32>;
DEF_ISEL(SBFM_64M_BITFIELD) = SBFM<R64W, R64, I64>;

DEF_ISEL(BFM_32M_BITFIELD) = BFM<R32W, R32, I32>;
DEF_ISEL(BFM_64M_BITFIELD) = BFM<R64W, R64, I64>;

namespace {

template <typename D, typename S, typename I>
DEF_SEM(EXTR, D dst, S src1, S src2, I src3) {
  using T = typename BaseType<S>::BT;
  constexpr auto size = T(sizeof(T) * 8);
  auto lsb = Read(src3);
  if (!lsb) {
    WriteZExt(dst, Read(src2));
  } else {
    auto operand1 = UShl(Read(src1), USub(size, lsb));
    auto operand2 = UShr(Read(src2), lsb);
    WriteZExt(dst, UOr(operand1, operand2));
  }
  return memory;
}

}  // namespace

DEF_ISEL(EXTR_32_EXTRACT) = EXTR<R32W, R32, I32>;
DEF_ISEL(EXTR_64_EXTRACT) = EXTR<R64W, R64, I64>;
