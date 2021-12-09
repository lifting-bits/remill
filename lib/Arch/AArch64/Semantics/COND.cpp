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

template <bool (*check_cond)(const State &), typename D, typename S1,
          typename S2>
DEF_SEM(CSEL, D dst, S1 src1, S2 src2) {
  auto val = check_cond(state) ? Read(src1) : Read(src2);
  WriteZExt(dst, val);
  return memory;
}
}  // namespace

#define DEF_COND_ISEL(isel, sem, ...) \
  DEF_ISEL(isel##_GE) = sem<CondGE, __VA_ARGS__>; \
  DEF_ISEL(isel##_GT) = sem<CondGT, __VA_ARGS__>; \
  DEF_ISEL(isel##_LE) = sem<CondLE, __VA_ARGS__>; \
  DEF_ISEL(isel##_LT) = sem<CondLT, __VA_ARGS__>; \
  DEF_ISEL(isel##_EQ) = sem<CondEQ, __VA_ARGS__>; \
  DEF_ISEL(isel##_NE) = sem<CondNE, __VA_ARGS__>; \
  DEF_ISEL(isel##_CS) = sem<CondCS, __VA_ARGS__>; \
  DEF_ISEL(isel##_CC) = sem<CondCC, __VA_ARGS__>; \
  DEF_ISEL(isel##_MI) = sem<CondMI, __VA_ARGS__>; \
  DEF_ISEL(isel##_PL) = sem<CondPL, __VA_ARGS__>; \
  DEF_ISEL(isel##_VS) = sem<CondVS, __VA_ARGS__>; \
  DEF_ISEL(isel##_VC) = sem<CondVC, __VA_ARGS__>; \
  DEF_ISEL(isel##_HI) = sem<CondHI, __VA_ARGS__>; \
  DEF_ISEL(isel##_LS) = sem<CondLS, __VA_ARGS__>; \
  DEF_ISEL(isel##_AL) = sem<CondAL, __VA_ARGS__>;

DEF_COND_ISEL(CSEL_32_CONDSEL, CSEL, R32W, R32, R32)
DEF_COND_ISEL(CSEL_64_CONDSEL, CSEL, R64W, R64, R64)

namespace {

template <bool (*check_cond)(const State &), typename D, typename S1,
          typename S2>
DEF_SEM(CSNEG, D dst, S1 src1, S2 src2) {
  WriteZExt(dst, Select(check_cond(state), Read(src1),
                        UAdd(UNot(Read(src2)), ZExtTo<S2>(1))));
  return memory;
}

}  // namespace


DEF_COND_ISEL(CSNEG_32_CONDSEL, CSNEG, R32W, R32, R32)
DEF_COND_ISEL(CSNEG_64_CONDSEL, CSNEG, R64W, R64, R64)

namespace {

template <bool (*check_cond)(const State &), typename D, typename S1,
          typename S2>
DEF_SEM(CSINC, D dst, S1 src1, S2 src2) {
  WriteZExt(dst, Select(check_cond(state), Read(src1), UAdd(Read(src2), 1)));
  return memory;
}
}  // namespace

DEF_COND_ISEL(CSINC_32_CONDSEL, CSINC, R32W, R32, R32)
DEF_COND_ISEL(CSINC_64_CONDSEL, CSINC, R64W, R64, R64)

namespace {

template <bool (*check_cond)(const State &), typename D, typename S1,
          typename S2>
DEF_SEM(CSINV, D dst, S1 src1, S2 src2) {
  WriteZExt(dst, Select(check_cond(state), Read(src1), UNot(Read(src2))));
  return memory;
}
}  // namespace

DEF_COND_ISEL(CSINV_32_CONDSEL, CSINV, R32W, R32, R32)
DEF_COND_ISEL(CSINV_64_CONDSEL, CSINV, R64W, R64, R64)

namespace {
template <bool (*check_cond)(const State &), typename S1, typename S2>
DEF_SEM(CCMP, S1 src1, S2 src2, S2 nzcv) {
  using T = typename BaseType<S1>::BT;
  if (check_cond(state)) {
    (void) AddWithCarryNZCV(state, Read(src1), UNot(Read(src2)), Read(src2),
                            T(1));
  } else {
    auto nzcv_val = Read(nzcv);
    FLAG_V = UCmpNeq(UAnd(nzcv_val, T(1)), T(0));
    FLAG_C = UCmpNeq(UAnd(nzcv_val, T(2)), T(0));
    FLAG_Z = UCmpNeq(UAnd(nzcv_val, T(4)), T(0));
    FLAG_N = UCmpNeq(UAnd(nzcv_val, T(8)), T(0));
  }
  return memory;
}

template <bool (*check_cond)(const State &), typename S1, typename S2>
DEF_SEM(CCMN, S1 src1, S2 src2, S2 nzcv) {
  using T = typename BaseType<S1>::BT;
  if (check_cond(state)) {
    (void) AddWithCarryNZCV(state, Read(src1), Read(src2), Read(src2), T(0));
  } else {
    auto nzcv_val = Read(nzcv);
    FLAG_V = UCmpNeq(UAnd(nzcv_val, T(1)), T(0));
    FLAG_C = UCmpNeq(UAnd(nzcv_val, T(2)), T(0));
    FLAG_Z = UCmpNeq(UAnd(nzcv_val, T(4)), T(0));
    FLAG_N = UCmpNeq(UAnd(nzcv_val, T(8)), T(0));
  }
  return memory;
}
}  // namespace

DEF_COND_ISEL(CCMP_32_CONDCMP_IMM, CCMP, R32, I32)
DEF_COND_ISEL(CCMP_64_CONDCMP_IMM, CCMP, R64, I64)

DEF_COND_ISEL(CCMP_32_CONDCMP_REG, CCMP, R32, R32)
DEF_COND_ISEL(CCMP_64_CONDCMP_REG, CCMP, R64, R64)

DEF_COND_ISEL(CCMN_32_CONDCMP_IMM, CCMN, R32, I32)
DEF_COND_ISEL(CCMN_64_CONDCMP_IMM, CCMN, R64, I64)
