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
DEF_SEM(EOR_REG, D dst, S1 src1, S2 src2) {
  WriteZExt(dst, UXor(Read(src1), Read(src2)));
  return memory;
}

}  // namespace

// DEF_ISEL() = SUB<M32W, M32, R32>;

DEF_ISEL(SUB_R64W_R64_R64) = SUB<R64W, R64, R64>;
DEF_ISEL(SUB_R64W_R64_U) = SUB<R64W, R64, I64>;

DEF_ISEL(ADD_R64W_R64_R64) = ADD<R64W, R64, R64>;
DEF_ISEL(ADD_R64W_R64_U) = ADD<R64W, R64, I64>;

DEF_ISEL(ASR_R64W_R64_U) = ASR<R64W, R64, I64>;

DEF_ISEL(EOR_R64W_R64_R64) = EOR_REG<R64W, R64, R64>;

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

DEF_ISEL(CMP_XFL_R64_R64) = CMP<R64, R64>;
DEF_ISEL(CMP_XFL_R64_U) = CMP<R64, I64>;

}  // namespace
