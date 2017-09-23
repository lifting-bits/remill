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

//integer d = UInt(Rd);
//integer n = UInt(Rn);
//integer datasize = if sf == '1' then 64 else 32;
//integer R; integer S; bits(datasize) wmask;
//bits(datasize) tmask;
//if sf == '1' && N != '1' then ReservedValue();
//if sf == '0' && (N != '0' || immr<5> != '0' || imms<5> != '0') then ReservedValue();
//
//R = UInt(immr);
//S = UInt(imms);
//(wmask, tmask) = DecodeBitMasks(N, imms, immr, FALSE);
//
//bits(datasize) src = X[n];
//
//// perform bitfield move on low bits
//bits(datasize) bot = ROR(src, R) AND wmask;
//
//// determine extension bits (sign, zero or dest register)
//bits(datasize) top = Replicate(src<S>);
//
//// combine extension bits and result bits
//X[d] = (top AND NOT(tmask)) OR (bot AND tmask);

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

}  // namespace

DEF_ISEL(UBFM_32M_BITFIELD) = UBFM<R32W, R32, I32>;
DEF_ISEL(UBFM_64M_BITFIELD) = UBFM<R64W, R64, I64>;

DEF_ISEL(SBFM_32M_BITFIELD) = SBFM<R32W, R32, I32>;
DEF_ISEL(SBFM_64M_BITFIELD) = SBFM<R64W, R64, I64>;

//DEF_ISEL(UBFIZ_UBFM_32M_BITFIELD) = UBFM<R32W, R32, I32>;
//DEF_ISEL(UBFIZ_UBFM_64M_BITFIELD) = UBFM<R64W, R64, I64>;
//
//DEF_ISEL(UBFX_UBFM_32M_BITFIELD) = UBFM<R32W, R32, I32>;
//DEF_ISEL(UBFX_UBFM_64M_BITFIELD) = UBFM<R64W, R64, I64>;
