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

}  // namespace

DEF_ISEL(UBFM_32M_BITFIELD) = UBFM<R32W, R32, I32>;
DEF_ISEL(UBFM_64M_BITFIELD) = UBFM<R64W, R64, I64>;

DEF_ISEL(UBFIZ_UBFM_32M_BITFIELD) = UBFM<R32W, R32, I32>;
DEF_ISEL(UBFIZ_UBFM_64M_BITFIELD) = UBFM<R64W, R64, I64>;
