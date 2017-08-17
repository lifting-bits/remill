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

template <typename D, typename S1, typename S2>
DEF_SEM(ASR, D dst, S1 src1, S2 src2) {
  WriteZExt(dst, Unsigned(SShr(Signed(Read(src1)), Signed(Read(src2)))));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(LSR, D dst, S1 src1, S2 src2) {
  WriteZExt(dst, UShr(Read(src1), Read(src2)));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(LSL, D dst, S1 src1, S2 src2) {
  WriteZExt(dst, UShl(Read(src1), Read(src2)));
  return memory;
}

}  // namespace

DEF_ISEL(ASR_SBFM_32M_BITFIELD) = ASR<R32W, R32, I32>;
DEF_ISEL(ASR_SBFM_64M_BITFIELD) = ASR<R64W, R64, I64>;

DEF_ISEL(LSR_UBFM_32M_BITFIELD) = LSR<R32W, R32, I32>;
DEF_ISEL(LSR_UBFM_64M_BITFIELD) = LSR<R64W, R64, I64>;

DEF_ISEL(LSL_UBFM_32M_BITFIELD) = LSL<R32W, R32, I32>;
DEF_ISEL(LSL_UBFM_64M_BITFIELD) = LSL<R64W, R64, I64>;
