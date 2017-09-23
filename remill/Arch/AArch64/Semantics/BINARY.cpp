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
DEF_SEM(EOR, D dst, S1 src1, S2 src2) {
  WriteZExt(dst, UXor(Read(src1), Read(src2)));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(AND, D dst, S1 src1, S2 src2) {
  WriteZExt(dst, UAnd(Read(src1), Read(src2)));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(ORR, D dst, S1 src1, S2 src2) {
  WriteZExt(dst, UOr(Read(src1), Read(src2)));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(BIC, D dst, S1 src1, S2 src2) {
  WriteZExt(dst, UAnd(Read(src1), UNot(Read(src2))));
  return memory;
}
}  // namespace

DEF_ISEL(ADD_32_ADDSUB_IMM) = ADD<R32W, R32, I32>;
DEF_ISEL(ADD_64_ADDSUB_IMM) = ADD<R64W, R64, I64>;
DEF_ISEL(ADD_32_ADDSUB_SHIFT) = ADD<R32W, R32, I32>;
DEF_ISEL(ADD_64_ADDSUB_SHIFT) = ADD<R64W, R64, I64>;
DEF_ISEL(ADD_32_ADDSUB_EXT) = ADD<R32W, R32, I32>;
DEF_ISEL(ADD_64_ADDSUB_EXT) = ADD<R64W, R64, I64>;

DEF_ISEL(SUB_32_ADDSUB_IMM) = SUB<R32W, R32, I32>;
DEF_ISEL(SUB_64_ADDSUB_IMM) = SUB<R64W, R64, I64>;
DEF_ISEL(SUB_32_ADDSUB_SHIFT) = SUB<R32W, R32, I32>;
DEF_ISEL(SUB_64_ADDSUB_SHIFT) = SUB<R64W, R64, I64>;
DEF_ISEL(SUB_32_ADDSUB_EXT) = SUB<R32W, R32, I32>;
DEF_ISEL(SUB_64_ADDSUB_EXT) = SUB<R64W, R64, I64>;

DEF_ISEL(EOR_32_LOG_SHIFT) = EOR<R32W, R32, I32>;
DEF_ISEL(EOR_64_LOG_SHIFT) = EOR<R64W, R64, I64>;
DEF_ISEL(EOR_32_LOG_IMM) = EOR<R32W, R32, I32>;
DEF_ISEL(EOR_64_LOG_IMM) = EOR<R64W, R64, I64>;

DEF_ISEL(AND_32_LOG_SHIFT) = AND<R32W, R32, I32>;
DEF_ISEL(AND_64_LOG_SHIFT) = AND<R64W, R64, I64>;
DEF_ISEL(AND_32_LOG_IMM) = AND<R32W, R32, I32>;
DEF_ISEL(AND_64_LOG_IMM) = AND<R64W, R64, I64>;

DEF_ISEL(ORR_32_LOG_SHIFT) = ORR<R32W, R32, I32>;
DEF_ISEL(ORR_64_LOG_SHIFT) = ORR<R64W, R64, I64>;
DEF_ISEL(ORR_32_LOG_IMM) = ORR<R32W, R32, I32>;
DEF_ISEL(ORR_64_LOG_IMM) = ORR<R64W, R64, I64>;

DEF_ISEL(BIC_32_LOG_SHIFT) = BIC<R32W, R32, I32>;
DEF_ISEL(BIC_64_LOG_SHIFT) = BIC<R64W, R64, I64>;

//namespace {
//
//template <typename S1, typename S2>
//DEF_SEM(CMP, S1 src1, S2 src2) {
//  using T = typename BaseType<S2>::BT;
//  auto lhs = Read(src1);
//  auto rhs = Read(src2);
//  auto res = USub(lhs, rhs);
//
//  auto rhs_comp = UNot(rhs);
//  auto add2c_inter = UAdd(lhs, rhs_comp);
//  auto add2c_final = UAdd(add2c_inter, T(1));
//
//  FLAG_Z = ZeroFlag(res);
//  FLAG_N = SignFlag(res);
//  FLAG_V = Overflow<tag_sub>::Flag(lhs, rhs, res);
//  FLAG_C = Carry<tag_add>::Flag(lhs, rhs_comp, add2c_inter) ||
//           Carry<tag_add>::Flag<T>(add2c_inter, T(1), add2c_final);
//  return memory;
//}
//
//template <typename S1, typename S2>
//DEF_SEM(CMN, S1 src1, S2 src2) {
//  auto lhs = Read(src1);
//  auto rhs = Read(src2);
//  auto res = UAdd(lhs, rhs);
//
//  FLAG_Z = ZeroFlag(res);
//  FLAG_N = SignFlag(res);
//  FLAG_V = Overflow<tag_add>::Flag(lhs, rhs, res);
//  FLAG_C = Carry<tag_add>::Flag(lhs, rhs, res);
//  return memory;
//}
//
//}  // namespace
//
//DEF_ISEL(CMP_SUBS_32_ADDSUB_SHIFT) = CMP<R32, I32>;
//DEF_ISEL(CMP_SUBS_64_ADDSUB_SHIFT) = CMP<R64, I64>;
//
//DEF_ISEL(CMP_SUBS_32S_ADDSUB_IMM) = CMP<R32, I32>;
//DEF_ISEL(CMP_SUBS_64S_ADDSUB_IMM) = CMP<R64, I64>;
//
//DEF_ISEL(CMP_SUBS_32S_ADDSUB_EXT) = CMP<R32, I32>;
//DEF_ISEL(CMP_SUBS_64S_ADDSUB_EXT) = CMP<R64, I64>;
//
//DEF_ISEL(CMN_ADDS_32_ADDSUB_SHIFT) = CMN<R32, I32>;
//DEF_ISEL(CMN_ADDS_64_ADDSUB_SHIFT) = CMN<R64, I64>;
//
//DEF_ISEL(CMN_ADDS_32S_ADDSUB_IMM) = CMN<R32, I32>;
//DEF_ISEL(CMN_ADDS_64S_ADDSUB_IMM) = CMN<R64, I64>;
//
//DEF_ISEL(CMN_ADDS_32S_ADDSUB_EXT) = CMN<R32, I32>;
//DEF_ISEL(CMN_ADDS_64S_ADDSUB_EXT) = CMN<R64, I64>;

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(SUBS, D dst, S1 src1, S2 src2) {
  using T = typename BaseType<S2>::BT;
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = USub(lhs, rhs);

  auto rhs_comp = UNot(rhs);
  auto add2c_inter = UAdd(lhs, rhs_comp);
  auto add2c_final = UAdd(add2c_inter, T(1));

  FLAG_Z = ZeroFlag(res);
  FLAG_N = SignFlag(res);
  FLAG_V = Overflow<tag_sub>::Flag(lhs, rhs, res);
  FLAG_C = Carry<tag_add>::Flag(lhs, rhs_comp, add2c_inter) ||
           Carry<tag_add>::Flag<T>(add2c_inter, T(1), add2c_final);

  WriteZExt(dst, res);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(ADDS, D dst, S1 src1, S2 src2) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UAdd(lhs, rhs);

  FLAG_Z = ZeroFlag(res);
  FLAG_N = SignFlag(res);
  FLAG_V = Overflow<tag_add>::Flag(lhs, rhs, res);
  FLAG_C = Carry<tag_add>::Flag(lhs, rhs, res);

  WriteZExt(dst, res);
  return memory;
}

}  // namespace

DEF_ISEL(SUBS_32_ADDSUB_SHIFT) = SUBS<R32W, R32, I32>;
DEF_ISEL(SUBS_64_ADDSUB_SHIFT) = SUBS<R64W, R64, I64>;
DEF_ISEL(SUBS_32S_ADDSUB_IMM) = SUBS<R32W, R32, I32>;
DEF_ISEL(SUBS_64S_ADDSUB_IMM) = SUBS<R64W, R64, I64>;
DEF_ISEL(SUBS_32S_ADDSUB_EXT) = SUBS<R32W, R32, I32>;
DEF_ISEL(SUBS_64S_ADDSUB_EXT) = SUBS<R64W, R64, I64>;

DEF_ISEL(ADDS_32_ADDSUB_SHIFT) = ADDS<R32W, R32, I32>;
DEF_ISEL(ADDS_64_ADDSUB_SHIFT) = ADDS<R64W, R64, I64>;
DEF_ISEL(ADDS_32S_ADDSUB_IMM) = ADDS<R32W, R32, I32>;
DEF_ISEL(ADDS_64S_ADDSUB_IMM) = ADDS<R64W, R64, I64>;
DEF_ISEL(ADDS_32S_ADDSUB_EXT) = ADDS<R32W, R32, I32>;
DEF_ISEL(ADDS_64S_ADDSUB_EXT) = ADDS<R64W, R64, I64>;

namespace {

//DEF_SEM(UMULL, R64W dst, R32 src1, R32 src2) {
//  Write(dst, UMul(ZExt(Read(src1)), ZExt(Read(src2))));
//  return memory;
//}

DEF_SEM(UMADDL, R64W dst, R32 src1, R32 src2, R64 src3) {
  Write(dst, UAdd(Read(src3), UMul(ZExt(Read(src1)), ZExt(Read(src2)))));
  return memory;
}

DEF_SEM(UMULH, R64W dst, R64 src1, R64 src2) {
  uint128_t lhs = ZExt(Read(src1));
  uint128_t rhs = ZExt(Read(src2));
  uint128_t res = UMul(lhs, rhs);
  Write(dst, Trunc(UShr(res, 64)));
  return memory;
}

template <typename D, typename S>
DEF_SEM(UDIV, D dst, S src1, S src2) {
  using T = typename BaseType<S>::BT;
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  if (!rhs) {
    WriteZExt(dst, T(0));
  } else {
    WriteZExt(dst, UDiv(lhs, rhs));
  }
  return memory;
}

}  // namespace

//DEF_ISEL(UMULL_UMADDL_64WA_DP_3SRC) = UMULL;

DEF_ISEL(UMADDL_64WA_DP_3SRC) = UMADDL;

DEF_ISEL(UMULH_64_DP_3SRC) = UMULH;
DEF_ISEL(UDIV_32_DP_2SRC) = UDIV<R32W, R32>;
DEF_ISEL(UDIV_64_DP_2SRC) = UDIV<R64W, R64>;

