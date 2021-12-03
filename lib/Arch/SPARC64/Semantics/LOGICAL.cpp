/*
 * Copyright (c) 2019 Trail of Bits, Inc.
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

#pragma once

namespace {

ALWAYS_INLINE void SetFlagsLogical(State &state, uint64_t lhs, uint64_t rhs,
                                   uint64_t res) {
  const auto res_32 = static_cast<uint32_t>(res);
  FLAG_ICC_CF = false;
  FLAG_ICC_ZF = ZeroFlag(res_32, lhs, rhs);
  FLAG_ICC_NF = SignFlag(res_32, lhs, rhs);
  FLAG_ICC_VF = false;

  FLAG_XCC_CF = false;
  FLAG_XCC_ZF = ZeroFlag(res, lhs, rhs);
  FLAG_XCC_NF = SignFlag(res, lhs, rhs);
  FLAG_XCC_VF = false;
}

}  // namespace

// Logical Operations
namespace {

template <typename S1, typename S2, typename D>
DEF_SEM(AND, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UAnd(lhs, rhs);
  WriteZExt(dst, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(ANDCC, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UAnd(lhs, rhs);
  WriteZExt(dst, res);
  SetFlagsLogical(state, lhs, rhs, res);
  return memory;
}

}  // namespace

// AND, ANDcc
DEF_ISEL(AND) = AND<R64, R64, R64W>;
DEF_ISEL(ANDcc) = ANDCC<R64, R64, R64W>;

namespace {

template <typename S1, typename S2, typename D>
DEF_SEM(ANDN, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UAnd(lhs, UNot(rhs));
  WriteZExt(dst, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(ANDNCC, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UAnd(lhs, UNot(rhs));
  WriteZExt(dst, res);
  SetFlagsLogical(state, lhs, rhs, res);
  return memory;
}

}  // namespace

// ANDN, ANDNcc
DEF_ISEL(ANDN) = ANDN<R64, R64, R64W>;
DEF_ISEL(ANDNcc) = ANDNCC<R64, R64, R64W>;

namespace {

template <typename S1, typename S2, typename D>
DEF_SEM(OR, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UOr(lhs, rhs);
  Write(dst, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(ORCC, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UOr(lhs, rhs);
  Write(dst, res);
  SetFlagsLogical(state, lhs, rhs, res);
  return memory;
}

}  // namespace

DEF_ISEL(OR) = OR<R64, R64, R64W>;
DEF_ISEL(ORcc) = ORCC<R64, R64, R64W>;

namespace {

template <typename S1, typename S2, typename D>
DEF_SEM(ORN, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UOr(lhs, UNot(rhs));
  WriteZExt(dst, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(ORNCC, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UOr(lhs, UNot(rhs));
  WriteZExt(dst, res);
  SetFlagsLogical(state, lhs, rhs, res);
  return memory;
}

}  // namespace

DEF_ISEL(ORN) = ORN<R64, R64, R64W>;
DEF_ISEL(ORNcc) = ORNCC<R64, R64, R64W>;

namespace {

template <typename S1, typename S2, typename D>
DEF_SEM(XOR, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UXor(lhs, rhs);
  WriteZExt(dst, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(XORCC, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UXor(lhs, rhs);
  WriteZExt(dst, res);
  SetFlagsLogical(state, lhs, rhs, res);
  return memory;
}

}  // namespace

DEF_ISEL(XOR) = XOR<R64, R64, R64W>;
DEF_ISEL(XORcc) = XORCC<R64, R64, R64W>;

namespace {

template <typename S1, typename S2, typename D>
DEF_SEM(XNOR, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UXor(lhs, UNot(rhs));
  WriteZExt(dst, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(XNORCC, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UXor(lhs, UNot(rhs));
  WriteZExt(dst, res);
  SetFlagsLogical(state, lhs, rhs, res);
  return memory;
}

}  // namespace

DEF_ISEL(XNOR) = XNOR<R64, R64, R64W>;
DEF_ISEL(XNORcc) = XNORCC<R64, R64, R64W>;

namespace {

template <typename S1, typename S2, typename D>
DEF_SEM(SLL, S1 src1, S2 src2, D dst) {
  auto value = Read(src1);
  auto shift = Read(src2);
  auto res = UShl(value, shift);
  WriteZExt(dst, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(SRL, S1 src1, S2 src2, D dst) {
  auto value = Read(src1);
  auto shift = Read(src2);
  auto res = UShr(value, shift);
  WriteZExt(dst, res);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(SRA, S1 src1, S2 src2, D dst) {
  auto val = Signed(Read(src1));
  auto shift = Read(src2);
  auto res = SShr(val, Signed(shift));
  WriteSExt(dst, res);
  return memory;
}

}  // namespace

DEF_ISEL(SLL) = SLL<R64, I64, R64W>;
DEF_ISEL(SRL) = SRL<R32, I32, R64W>;
DEF_ISEL(SRA) = SRA<R32, I32, R64W>;

DEF_ISEL(SLLX) = SLL<R64, I64, R64W>;
DEF_ISEL(SRLX) = SRL<R64, I64, R64W>;
DEF_ISEL(SRAX) = SRA<R64, I64, R64W>;
