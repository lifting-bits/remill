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

template <bool (*check_cond)(const State &), typename D, typename S1, typename S2>
DEF_SEM(CSEL, D dst, S1 src1, S2 src2) {
    auto val = check_cond(state) ? Read(src1) : Read(src2);
    WriteZExt(dst, val);
    return memory;
}
} // namespace

DEF_ISEL(CSEL_32_CONDSEL_GE) = CSEL<CondGE, R32W, R32, R32>;
DEF_ISEL(CSEL_32_CONDSEL_GT) = CSEL<CondGT, R32W, R32, R32>;
DEF_ISEL(CSEL_32_CONDSEL_LE) = CSEL<CondLE, R32W, R32, R32>;
DEF_ISEL(CSEL_32_CONDSEL_LT) = CSEL<CondLT, R32W, R32, R32>;
DEF_ISEL(CSEL_32_CONDSEL_EQ) = CSEL<CondEQ, R32W, R32, R32>;
DEF_ISEL(CSEL_32_CONDSEL_NE) = CSEL<CondNE, R32W, R32, R32>;
DEF_ISEL(CSEL_32_CONDSEL_CS) = CSEL<CondCS, R32W, R32, R32>;
DEF_ISEL(CSEL_32_CONDSEL_CC) = CSEL<CondCC, R32W, R32, R32>;
DEF_ISEL(CSEL_32_CONDSEL_MI) = CSEL<CondMI, R32W, R32, R32>;
DEF_ISEL(CSEL_32_CONDSEL_PL) = CSEL<CondPL, R32W, R32, R32>;
DEF_ISEL(CSEL_32_CONDSEL_VS) = CSEL<CondVS, R32W, R32, R32>;
DEF_ISEL(CSEL_32_CONDSEL_VC) = CSEL<CondVC, R32W, R32, R32>;
DEF_ISEL(CSEL_32_CONDSEL_HI) = CSEL<CondHI, R32W, R32, R32>;
DEF_ISEL(CSEL_32_CONDSEL_LS) = CSEL<CondLS, R32W, R32, R32>;
DEF_ISEL(CSEL_32_CONDSEL_AL) = CSEL<CondAL, R32W, R32, R32>;

DEF_ISEL(CSEL_64_CONDSEL_GE) = CSEL<CondGE, R64W, R64, R64>;
DEF_ISEL(CSEL_64_CONDSEL_GT) = CSEL<CondGT, R64W, R64, R64>;
DEF_ISEL(CSEL_64_CONDSEL_LE) = CSEL<CondLE, R64W, R64, R64>;
DEF_ISEL(CSEL_64_CONDSEL_LT) = CSEL<CondLT, R64W, R64, R64>;
DEF_ISEL(CSEL_64_CONDSEL_EQ) = CSEL<CondEQ, R64W, R64, R64>;
DEF_ISEL(CSEL_64_CONDSEL_NE) = CSEL<CondNE, R64W, R64, R64>;
DEF_ISEL(CSEL_64_CONDSEL_CS) = CSEL<CondCS, R64W, R64, R64>;
DEF_ISEL(CSEL_64_CONDSEL_CC) = CSEL<CondCC, R64W, R64, R64>;
DEF_ISEL(CSEL_64_CONDSEL_MI) = CSEL<CondMI, R64W, R64, R64>;
DEF_ISEL(CSEL_64_CONDSEL_PL) = CSEL<CondPL, R64W, R64, R64>;
DEF_ISEL(CSEL_64_CONDSEL_VS) = CSEL<CondVS, R64W, R64, R64>;
DEF_ISEL(CSEL_64_CONDSEL_VC) = CSEL<CondVC, R64W, R64, R64>;
DEF_ISEL(CSEL_64_CONDSEL_HI) = CSEL<CondHI, R64W, R64, R64>;
DEF_ISEL(CSEL_64_CONDSEL_LS) = CSEL<CondLS, R64W, R64, R64>;
DEF_ISEL(CSEL_64_CONDSEL_AL) = CSEL<CondAL, R64W, R64, R64>;

namespace {

template <bool (*check_cond)(const State &), typename D, typename S1, typename S2>
DEF_SEM(CSINC, D dst, S1 src1, S2 src2)  {
  auto val = check_cond(state)? Read(src1) : UAdd(Read(src2), 1);
  WriteZExt(dst, val);
  return memory;
}

template <bool (*check_cond)(const State &), typename D, typename S>
DEF_SEM(CINC, D dst, S src)  {
  auto reg = Read(src);
  auto val = check_cond(state)? UAdd(reg, 1) : reg;
  WriteZExt(dst, val);
  return memory;
}

// The WZR/XZR register as 2nd operand is implicitly passed
template <bool (*check_cond)(const State &), typename D, typename S>
DEF_SEM(CSET, D dst, S src)  {
  auto zero_reg = Read(src);
  auto val = check_cond(state)?  UAdd(zero_reg, 1) : zero_reg;
  WriteZExt(dst, val);
  return memory;
}
}  // namespace

DEF_ISEL(CSINC_32_CONDSEL_GE) = CSINC<CondGE, R32W, R32, R32>;
DEF_ISEL(CSINC_32_CONDSEL_GT) = CSINC<CondGT, R32W, R32, R32>;
DEF_ISEL(CSINC_32_CONDSEL_LE) = CSINC<CondLE, R32W, R32, R32>;
DEF_ISEL(CSINC_32_CONDSEL_LT) = CSINC<CondLT, R32W, R32, R32>;
DEF_ISEL(CSINC_32_CONDSEL_EQ) = CSINC<CondEQ, R32W, R32, R32>;
DEF_ISEL(CSINC_32_CONDSEL_NE) = CSINC<CondNE, R32W, R32, R32>;
DEF_ISEL(CSINC_32_CONDSEL_CS) = CSINC<CondCS, R32W, R32, R32>;
DEF_ISEL(CSINC_32_CONDSEL_CC) = CSINC<CondCC, R32W, R32, R32>;
DEF_ISEL(CSINC_32_CONDSEL_MI) = CSINC<CondMI, R32W, R32, R32>;
DEF_ISEL(CSINC_32_CONDSEL_PL) = CSINC<CondPL, R32W, R32, R32>;
DEF_ISEL(CSINC_32_CONDSEL_VS) = CSINC<CondVS, R32W, R32, R32>;
DEF_ISEL(CSINC_32_CONDSEL_VC) = CSINC<CondVC, R32W, R32, R32>;
DEF_ISEL(CSINC_32_CONDSEL_HI) = CSINC<CondHI, R32W, R32, R32>;
DEF_ISEL(CSINC_32_CONDSEL_LS) = CSINC<CondLS, R32W, R32, R32>;
DEF_ISEL(CSINC_32_CONDSEL_AL) = CSINC<CondAL, R32W, R32, R32>;

DEF_ISEL(CSINC_64_CONDSEL_GE) = CSINC<CondGE, R64W, R64, R64>;
DEF_ISEL(CSINC_64_CONDSEL_GT) = CSINC<CondGT, R64W, R64, R64>;
DEF_ISEL(CSINC_64_CONDSEL_LE) = CSINC<CondLE, R64W, R64, R64>;
DEF_ISEL(CSINC_64_CONDSEL_LT) = CSINC<CondLT, R64W, R64, R64>;
DEF_ISEL(CSINC_64_CONDSEL_EQ) = CSINC<CondEQ, R64W, R64, R64>;
DEF_ISEL(CSINC_64_CONDSEL_NE) = CSINC<CondNE, R64W, R64, R64>;
DEF_ISEL(CSINC_64_CONDSEL_CS) = CSINC<CondCS, R64W, R64, R64>;
DEF_ISEL(CSINC_64_CONDSEL_CC) = CSINC<CondCC, R64W, R64, R64>;
DEF_ISEL(CSINC_64_CONDSEL_MI) = CSINC<CondMI, R64W, R64, R64>;
DEF_ISEL(CSINC_64_CONDSEL_PL) = CSINC<CondPL, R64W, R64, R64>;
DEF_ISEL(CSINC_64_CONDSEL_VS) = CSINC<CondVS, R64W, R64, R64>;
DEF_ISEL(CSINC_64_CONDSEL_VC) = CSINC<CondVC, R64W, R64, R64>;
DEF_ISEL(CSINC_64_CONDSEL_HI) = CSINC<CondHI, R64W, R64, R64>;
DEF_ISEL(CSINC_64_CONDSEL_LS) = CSINC<CondLS, R64W, R64, R64>;
DEF_ISEL(CSINC_64_CONDSEL_AL) = CSINC<CondAL, R64W, R64, R64>;

DEF_ISEL(CINC_CSINC_32_CONDSEL_GE) = CINC<CondGE, R32W, R32>;
DEF_ISEL(CINC_CSINC_32_CONDSEL_GT) = CINC<CondGT, R32W, R32>;
DEF_ISEL(CINC_CSINC_32_CONDSEL_LE) = CINC<CondLE, R32W, R32>;
DEF_ISEL(CINC_CSINC_32_CONDSEL_LT) = CINC<CondLT, R32W, R32>;
DEF_ISEL(CINC_CSINC_32_CONDSEL_EQ) = CINC<CondEQ, R32W, R32>;
DEF_ISEL(CINC_CSINC_32_CONDSEL_NE) = CINC<CondNE, R32W, R32>;
DEF_ISEL(CINC_CSINC_32_CONDSEL_CS) = CINC<CondCS, R32W, R32>;
DEF_ISEL(CINC_CSINC_32_CONDSEL_CC) = CINC<CondCC, R32W, R32>;
DEF_ISEL(CINC_CSINC_32_CONDSEL_MI) = CINC<CondMI, R32W, R32>;
DEF_ISEL(CINC_CSINC_32_CONDSEL_PL) = CINC<CondPL, R32W, R32>;
DEF_ISEL(CINC_CSINC_32_CONDSEL_VS) = CINC<CondVS, R32W, R32>;
DEF_ISEL(CINC_CSINC_32_CONDSEL_VC) = CINC<CondVC, R32W, R32>;
DEF_ISEL(CINC_CSINC_32_CONDSEL_HI) = CINC<CondHI, R32W, R32>;
DEF_ISEL(CINC_CSINC_32_CONDSEL_LS) = CINC<CondLS, R32W, R32>;
DEF_ISEL(CINC_CSINC_32_CONDSEL_AL) = CINC<CondAL, R32W, R32>;

DEF_ISEL(CINC_CSINC_64_CONDSEL_GE) = CINC<CondGE, R64W, R64>;
DEF_ISEL(CINC_CSINC_64_CONDSEL_GT) = CINC<CondGT, R64W, R64>;
DEF_ISEL(CINC_CSINC_64_CONDSEL_LE) = CINC<CondLE, R64W, R64>;
DEF_ISEL(CINC_CSINC_64_CONDSEL_LT) = CINC<CondLT, R64W, R64>;
DEF_ISEL(CINC_CSINC_64_CONDSEL_EQ) = CINC<CondEQ, R64W, R64>;
DEF_ISEL(CINC_CSINC_64_CONDSEL_NE) = CINC<CondNE, R64W, R64>;
DEF_ISEL(CINC_CSINC_64_CONDSEL_CS) = CINC<CondCS, R64W, R64>;
DEF_ISEL(CINC_CSINC_64_CONDSEL_CC) = CINC<CondCC, R64W, R64>;
DEF_ISEL(CINC_CSINC_64_CONDSEL_MI) = CINC<CondMI, R64W, R64>;
DEF_ISEL(CINC_CSINC_64_CONDSEL_PL) = CINC<CondPL, R64W, R64>;
DEF_ISEL(CINC_CSINC_64_CONDSEL_VS) = CINC<CondVS, R64W, R64>;
DEF_ISEL(CINC_CSINC_64_CONDSEL_VC) = CINC<CondVC, R64W, R64>;
DEF_ISEL(CINC_CSINC_64_CONDSEL_HI) = CINC<CondHI, R64W, R64>;
DEF_ISEL(CINC_CSINC_64_CONDSEL_LS) = CINC<CondLS, R64W, R64>;
DEF_ISEL(CINC_CSINC_64_CONDSEL_AL) = CINC<CondAL, R64W, R64>;

DEF_ISEL(CSET_CSINC_32_CONDSEL_GE) = CSET<CondGE, R32W, R32>;
DEF_ISEL(CSET_CSINC_32_CONDSEL_GT) = CSET<CondGT, R32W, R32>;
DEF_ISEL(CSET_CSINC_32_CONDSEL_LE) = CSET<CondLE, R32W, R32>;
DEF_ISEL(CSET_CSINC_32_CONDSEL_LT) = CSET<CondLT, R32W, R32>;
DEF_ISEL(CSET_CSINC_32_CONDSEL_EQ) = CSET<CondEQ, R32W, R32>;
DEF_ISEL(CSET_CSINC_32_CONDSEL_NE) = CSET<CondNE, R32W, R32>;
DEF_ISEL(CSET_CSINC_32_CONDSEL_CS) = CSET<CondCS, R32W, R32>;
DEF_ISEL(CSET_CSINC_32_CONDSEL_CC) = CSET<CondCC, R32W, R32>;
DEF_ISEL(CSET_CSINC_32_CONDSEL_MI) = CSET<CondMI, R32W, R32>;
DEF_ISEL(CSET_CSINC_32_CONDSEL_PL) = CSET<CondPL, R32W, R32>;
DEF_ISEL(CSET_CSINC_32_CONDSEL_VS) = CSET<CondVS, R32W, R32>;
DEF_ISEL(CSET_CSINC_32_CONDSEL_VC) = CSET<CondVC, R32W, R32>;
DEF_ISEL(CSET_CSINC_32_CONDSEL_HI) = CSET<CondHI, R32W, R32>;
DEF_ISEL(CSET_CSINC_32_CONDSEL_LS) = CSET<CondLS, R32W, R32>;
DEF_ISEL(CSET_CSINC_32_CONDSEL_AL) = CSET<CondAL, R32W, R32>;

DEF_ISEL(CSET_CSINC_64_CONDSEL_GE) = CSET<CondGE, R64W, R64>;
DEF_ISEL(CSET_CSINC_64_CONDSEL_GT) = CSET<CondGT, R64W, R64>;
DEF_ISEL(CSET_CSINC_64_CONDSEL_LE) = CSET<CondLE, R64W, R64>;
DEF_ISEL(CSET_CSINC_64_CONDSEL_LT) = CSET<CondLT, R64W, R64>;
DEF_ISEL(CSET_CSINC_64_CONDSEL_EQ) = CSET<CondEQ, R64W, R64>;
DEF_ISEL(CSET_CSINC_64_CONDSEL_NE) = CSET<CondNE, R64W, R64>;
DEF_ISEL(CSET_CSINC_64_CONDSEL_CS) = CSET<CondCS, R64W, R64>;
DEF_ISEL(CSET_CSINC_64_CONDSEL_CC) = CSET<CondCC, R64W, R64>;
DEF_ISEL(CSET_CSINC_64_CONDSEL_MI) = CSET<CondMI, R64W, R64>;
DEF_ISEL(CSET_CSINC_64_CONDSEL_PL) = CSET<CondPL, R64W, R64>;
DEF_ISEL(CSET_CSINC_64_CONDSEL_VS) = CSET<CondVS, R64W, R64>;
DEF_ISEL(CSET_CSINC_64_CONDSEL_VC) = CSET<CondVC, R64W, R64>;
DEF_ISEL(CSET_CSINC_64_CONDSEL_HI) = CSET<CondHI, R64W, R64>;
DEF_ISEL(CSET_CSINC_64_CONDSEL_LS) = CSET<CondLS, R64W, R64>;
DEF_ISEL(CSET_CSINC_64_CONDSEL_AL) = CSET<CondAL, R64W, R64>;

namespace {

template <bool (*check_cond)(const State &), typename D, typename S1, typename S2>
DEF_SEM(CSINV, D dst, S1 src1, S2 src2)  {
  auto val = check_cond(state)? Read(src1) : UNot(Read(src2));
  WriteZExt(dst, val);
  return memory;
}

template <bool (*check_cond)(const State &), typename D, typename S>
DEF_SEM(CINV, D dst, S src)  {
  auto reg = Read(src);
  auto val = check_cond(state)? UNot(reg) : reg;
  WriteZExt(dst, val);
  return memory;
}

// The WZR/XZR register as 2nd operand is implicitly passed and we need
// to use it to get correct bitmasking for our '0' to make sure
// we do/don't right bits to incorrect width of our register
template <bool (*check_cond)(const State &), typename D, typename S>
DEF_SEM(CSETM, D dst, S src)  {
  auto zero_reg = Read(src);
  auto val = check_cond(state)?  UNot(zero_reg) : zero_reg;
  WriteZExt(dst, val);
  return memory;
}
} // namespace

DEF_ISEL(CSINV_32_CONDSEL_GE) = CSINV<CondGE, R32W, R32, R32>;
DEF_ISEL(CSINV_32_CONDSEL_GT) = CSINV<CondGT, R32W, R32, R32>;
DEF_ISEL(CSINV_32_CONDSEL_LE) = CSINV<CondLE, R32W, R32, R32>;
DEF_ISEL(CSINV_32_CONDSEL_LT) = CSINV<CondLT, R32W, R32, R32>;
DEF_ISEL(CSINV_32_CONDSEL_EQ) = CSINV<CondEQ, R32W, R32, R32>;
DEF_ISEL(CSINV_32_CONDSEL_NE) = CSINV<CondNE, R32W, R32, R32>;
DEF_ISEL(CSINV_32_CONDSEL_CS) = CSINV<CondCS, R32W, R32, R32>;
DEF_ISEL(CSINV_32_CONDSEL_CC) = CSINV<CondCC, R32W, R32, R32>;
DEF_ISEL(CSINV_32_CONDSEL_MI) = CSINV<CondMI, R32W, R32, R32>;
DEF_ISEL(CSINV_32_CONDSEL_PL) = CSINV<CondPL, R32W, R32, R32>;
DEF_ISEL(CSINV_32_CONDSEL_VS) = CSINV<CondVS, R32W, R32, R32>;
DEF_ISEL(CSINV_32_CONDSEL_VC) = CSINV<CondVC, R32W, R32, R32>;
DEF_ISEL(CSINV_32_CONDSEL_HI) = CSINV<CondHI, R32W, R32, R32>;
DEF_ISEL(CSINV_32_CONDSEL_LS) = CSINV<CondLS, R32W, R32, R32>;
DEF_ISEL(CSINV_32_CONDSEL_AL) = CSINV<CondAL, R32W, R32, R32>;

DEF_ISEL(CSINV_64_CONDSEL_GE) = CSINV<CondGE, R64W, R64, R64>;
DEF_ISEL(CSINV_64_CONDSEL_GT) = CSINV<CondGT, R64W, R64, R64>;
DEF_ISEL(CSINV_64_CONDSEL_LE) = CSINV<CondLE, R64W, R64, R64>;
DEF_ISEL(CSINV_64_CONDSEL_LT) = CSINV<CondLT, R64W, R64, R64>;
DEF_ISEL(CSINV_64_CONDSEL_EQ) = CSINV<CondEQ, R64W, R64, R64>;
DEF_ISEL(CSINV_64_CONDSEL_NE) = CSINV<CondNE, R64W, R64, R64>;
DEF_ISEL(CSINV_64_CONDSEL_CS) = CSINV<CondCS, R64W, R64, R64>;
DEF_ISEL(CSINV_64_CONDSEL_CC) = CSINV<CondCC, R64W, R64, R64>;
DEF_ISEL(CSINV_64_CONDSEL_MI) = CSINV<CondMI, R64W, R64, R64>;
DEF_ISEL(CSINV_64_CONDSEL_PL) = CSINV<CondPL, R64W, R64, R64>;
DEF_ISEL(CSINV_64_CONDSEL_VS) = CSINV<CondVS, R64W, R64, R64>;
DEF_ISEL(CSINV_64_CONDSEL_VC) = CSINV<CondVC, R64W, R64, R64>;
DEF_ISEL(CSINV_64_CONDSEL_HI) = CSINV<CondHI, R64W, R64, R64>;
DEF_ISEL(CSINV_64_CONDSEL_LS) = CSINV<CondLS, R64W, R64, R64>;
DEF_ISEL(CSINV_64_CONDSEL_AL) = CSINV<CondAL, R64W, R64, R64>;

DEF_ISEL(CINV_CSINV_32_CONDSEL_GE) = CINV<CondGE, R32W, R32>;
DEF_ISEL(CINV_CSINV_32_CONDSEL_GT) = CINV<CondGT, R32W, R32>;
DEF_ISEL(CINV_CSINV_32_CONDSEL_LE) = CINV<CondLE, R32W, R32>;
DEF_ISEL(CINV_CSINV_32_CONDSEL_LT) = CINV<CondLT, R32W, R32>;
DEF_ISEL(CINV_CSINV_32_CONDSEL_EQ) = CINV<CondEQ, R32W, R32>;
DEF_ISEL(CINV_CSINV_32_CONDSEL_NE) = CINV<CondNE, R32W, R32>;
DEF_ISEL(CINV_CSINV_32_CONDSEL_CS) = CINV<CondCS, R32W, R32>;
DEF_ISEL(CINV_CSINV_32_CONDSEL_CC) = CINV<CondCC, R32W, R32>;
DEF_ISEL(CINV_CSINV_32_CONDSEL_MI) = CINV<CondMI, R32W, R32>;
DEF_ISEL(CINV_CSINV_32_CONDSEL_PL) = CINV<CondPL, R32W, R32>;
DEF_ISEL(CINV_CSINV_32_CONDSEL_VS) = CINV<CondVS, R32W, R32>;
DEF_ISEL(CINV_CSINV_32_CONDSEL_VC) = CINV<CondVC, R32W, R32>;
DEF_ISEL(CINV_CSINV_32_CONDSEL_HI) = CINV<CondHI, R32W, R32>;
DEF_ISEL(CINV_CSINV_32_CONDSEL_LS) = CINV<CondLS, R32W, R32>;
DEF_ISEL(CINV_CSINV_32_CONDSEL_AL) = CINV<CondAL, R32W, R32>;

DEF_ISEL(CINV_CSINV_64_CONDSEL_GE) = CINV<CondGE, R64W, R64>;
DEF_ISEL(CINV_CSINV_64_CONDSEL_GT) = CINV<CondGT, R64W, R64>;
DEF_ISEL(CINV_CSINV_64_CONDSEL_LE) = CINV<CondLE, R64W, R64>;
DEF_ISEL(CINV_CSINV_64_CONDSEL_LT) = CINV<CondLT, R64W, R64>;
DEF_ISEL(CINV_CSINV_64_CONDSEL_EQ) = CINV<CondEQ, R64W, R64>;
DEF_ISEL(CINV_CSINV_64_CONDSEL_NE) = CINV<CondNE, R64W, R64>;
DEF_ISEL(CINV_CSINV_64_CONDSEL_CS) = CINV<CondCS, R64W, R64>;
DEF_ISEL(CINV_CSINV_64_CONDSEL_CC) = CINV<CondCC, R64W, R64>;
DEF_ISEL(CINV_CSINV_64_CONDSEL_MI) = CINV<CondMI, R64W, R64>;
DEF_ISEL(CINV_CSINV_64_CONDSEL_PL) = CINV<CondPL, R64W, R64>;
DEF_ISEL(CINV_CSINV_64_CONDSEL_VS) = CINV<CondVS, R64W, R64>;
DEF_ISEL(CINV_CSINV_64_CONDSEL_VC) = CINV<CondVC, R64W, R64>;
DEF_ISEL(CINV_CSINV_64_CONDSEL_HI) = CINV<CondHI, R64W, R64>;
DEF_ISEL(CINV_CSINV_64_CONDSEL_LS) = CINV<CondLS, R64W, R64>;
DEF_ISEL(CINV_CSINV_64_CONDSEL_AL) = CINV<CondAL, R64W, R64>;

DEF_ISEL(CSETM_CSINV_32_CONDSEL_GE) = CSETM<CondGE, R32W, R32>;
DEF_ISEL(CSETM_CSINV_32_CONDSEL_GT) = CSETM<CondGT, R32W, R32>;
DEF_ISEL(CSETM_CSINV_32_CONDSEL_LE) = CSETM<CondLE, R32W, R32>;
DEF_ISEL(CSETM_CSINV_32_CONDSEL_LT) = CSETM<CondLT, R32W, R32>;
DEF_ISEL(CSETM_CSINV_32_CONDSEL_EQ) = CSETM<CondEQ, R32W, R32>;
DEF_ISEL(CSETM_CSINV_32_CONDSEL_NE) = CSETM<CondNE, R32W, R32>;
DEF_ISEL(CSETM_CSINV_32_CONDSEL_CS) = CSETM<CondCS, R32W, R32>;
DEF_ISEL(CSETM_CSINV_32_CONDSEL_CC) = CSETM<CondCC, R32W, R32>;
DEF_ISEL(CSETM_CSINV_32_CONDSEL_MI) = CSETM<CondMI, R32W, R32>;
DEF_ISEL(CSETM_CSINV_32_CONDSEL_PL) = CSETM<CondPL, R32W, R32>;
DEF_ISEL(CSETM_CSINV_32_CONDSEL_VS) = CSETM<CondVS, R32W, R32>;
DEF_ISEL(CSETM_CSINV_32_CONDSEL_VC) = CSETM<CondVC, R32W, R32>;
DEF_ISEL(CSETM_CSINV_32_CONDSEL_HI) = CSETM<CondHI, R32W, R32>;
DEF_ISEL(CSETM_CSINV_32_CONDSEL_LS) = CSETM<CondLS, R32W, R32>;
DEF_ISEL(CSETM_CSINV_32_CONDSEL_AL) = CSETM<CondAL, R32W, R32>;

DEF_ISEL(CSETM_CSINV_64_CONDSEL_GE) = CSETM<CondGE, R64W, R64>;
DEF_ISEL(CSETM_CSINV_64_CONDSEL_GT) = CSETM<CondGT, R64W, R64>;
DEF_ISEL(CSETM_CSINV_64_CONDSEL_LE) = CSETM<CondLE, R64W, R64>;
DEF_ISEL(CSETM_CSINV_64_CONDSEL_LT) = CSETM<CondLT, R64W, R64>;
DEF_ISEL(CSETM_CSINV_64_CONDSEL_EQ) = CSETM<CondEQ, R64W, R64>;
DEF_ISEL(CSETM_CSINV_64_CONDSEL_NE) = CSETM<CondNE, R64W, R64>;
DEF_ISEL(CSETM_CSINV_64_CONDSEL_CS) = CSETM<CondCS, R64W, R64>;
DEF_ISEL(CSETM_CSINV_64_CONDSEL_CC) = CSETM<CondCC, R64W, R64>;
DEF_ISEL(CSETM_CSINV_64_CONDSEL_MI) = CSETM<CondMI, R64W, R64>;
DEF_ISEL(CSETM_CSINV_64_CONDSEL_PL) = CSETM<CondPL, R64W, R64>;
DEF_ISEL(CSETM_CSINV_64_CONDSEL_VS) = CSETM<CondVS, R64W, R64>;
DEF_ISEL(CSETM_CSINV_64_CONDSEL_VC) = CSETM<CondVC, R64W, R64>;
DEF_ISEL(CSETM_CSINV_64_CONDSEL_HI) = CSETM<CondHI, R64W, R64>;
DEF_ISEL(CSETM_CSINV_64_CONDSEL_LS) = CSETM<CondLS, R64W, R64>;
DEF_ISEL(CSETM_CSINV_64_CONDSEL_AL) = CSETM<CondAL, R64W, R64>;

namespace {

template <bool (*check_cond)(const State &), typename S1, typename S2>
DEF_SEM(CCMP, S1 src1, S2 src2, I8 nzcv) {
  using T = typename BaseType<S1>::BT;
  if (check_cond(state)) {
    auto lhs = Read(src1);
    auto rhs = ZExtTo<S1>(Read(src2));
    auto res = UAdd(lhs, rhs);

    auto rhs_comp = UNot(rhs);
    auto add2c_inter = UAdd(lhs, rhs_comp);
    auto add2c_final = UAdd(add2c_inter, T(1));

    FLAG_Z = ZeroFlag(res);
    FLAG_N = SignFlag(res);
    FLAG_V = Overflow<tag_sub>::Flag(lhs, rhs, res);
    FLAG_C = Carry<tag_add>::Flag(lhs, rhs_comp, add2c_inter) ||
            Carry<tag_add>::Flag<T>(add2c_inter, T(1), add2c_final);

    // auto operand1 = Read(src1);
    // auto operand2 = UNot(ZExtTo<S1>(Read(src2)));


    // auto add2c_inter = UAdd(ZExt(operand1), ZExt(operand2));
    // auto add2c_final = UAdd(add2c_inter, ZExt(T(1)));

    // auto signed_add2c_inter = Signed(SAdd(SExt(Signed(operand1)), SExt(Signed(operand2))));
    // auto signed_add2c_final = Signed(SAdd(SExt(Signed(signed_add2c_inter)), ZExt(T(1)))); // Specifies Uint(1)??

    // auto result = Trunc(add2c_final);

    // FLAG_Z = ZeroFlag(result);
    // FLAG_N = SignFlag(result);
    // FLAG_C = Unsigned(result) == add2c_final? 0 : 1;
    // FLAG_V = Signed(result) == signed_add2c_final? 0 : 1;
  } else {
    auto nzcv_val = ZExtTo<S1>(Read(nzcv));
    FLAG_V = UCmpNeq(UAnd(nzcv_val, T(1)), 0);
    FLAG_C = UCmpNeq(UAnd(nzcv_val, T(2)), 0);
    FLAG_Z = UCmpNeq(UAnd(nzcv_val, T(4)), 0);
    FLAG_N = UCmpNeq(UAnd(nzcv_val, T(8)), 0);
  }
  return memory;
}
} // namespace

DEF_ISEL(CCMP_32_CONDCMP_IMM_EQ) = CCMP<CondEQ, R32, I8>;