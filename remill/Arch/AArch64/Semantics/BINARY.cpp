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
DEF_SEM(SUB, D dst, S1 src1, S2 src2) {
  WriteZExt(dst, USub(Read(src1), Read(src2)));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(ADD, D dst, S1 src1, S2 src2) {
  WriteZExt(dst, UAdd(Read(src1), Read(src2)));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(ASR, D dst, S1 src1, S2 src2) {
  WriteZExt(dst, Unsigned(SShr(Signed(Read(src1)), Signed(Read(src2)))));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(EOR, D dst, S1 src1, S2 src2) {
  WriteZExt(dst, UXor(Read(src1), Read(src2)));
  return memory;
}

}  // namespace

DEF_ISEL(ADD_32_ADDSUB_IMM) = ADD<R32W, R32, I32>;
DEF_ISEL(ADD_64_ADDSUB_IMM) = ADD<R64W, R64, I64>;

DEF_ISEL(ADD_32_ADDSUB_SHIFT) = ADD<R32W, R32, R32>;
DEF_ISEL(ADD_64_ADDSUB_SHIFT) = ADD<R64W, R64, R64>;

DEF_ISEL(SUB_32_ADDSUB_IMM) = SUB<R32W, R32, I32>;
DEF_ISEL(SUB_64_ADDSUB_IMM) = SUB<R64W, R64, I64>;

DEF_ISEL(SUB_32_ADDSUB_SHIFT) = SUB<R32W, R32, R32>;
DEF_ISEL(SUB_64_ADDSUB_SHIFT) = SUB<R64W, R64, R64>;

DEF_ISEL(EOR_32_LOG_SHIFT) = EOR<R32W, R32, R32>;
DEF_ISEL(EOR_64_LOG_SHIFT) = EOR<R64W, R64, R64>;

DEF_ISEL(EOR_32_LOG_IMM) = EOR<R32W, R32, I32>;
DEF_ISEL(EOR_64_LOG_IMM) = EOR<R64W, R64, I64>;

namespace {

template <typename S1, typename S2>
DEF_SEM(CMP, S1 src1, S2 src2) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = USub(lhs, rhs);
  FLAG_Z = ZeroFlag(res);
  FLAG_N = SignFlag(res);
  FLAG_V = Overflow<tag_sub>::Flag(lhs, rhs, res);
  FLAG_C = Carry<tag_sub>::Flag(lhs, rhs, res);
  return memory;
}

DEF_ISEL(CMP_SUBS_32_ADDSUB_SHIFT) = CMP<R32, R32>;
DEF_ISEL(CMP_SUBS_64_ADDSUB_SHIFT) = CMP<R64, R64>;

DEF_ISEL(CMP_SUBS_32S_ADDSUB_IMM) = CMP<R32, I32>;
DEF_ISEL(CMP_SUBS_64S_ADDSUB_IMM) = CMP<R64, I64>;

}  // namespace
