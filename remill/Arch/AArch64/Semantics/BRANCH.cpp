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

static inline bool CondGE(const State &state) {
  return UCmpNeq(state.state.GE, 0);
}

static inline bool CondLT(const State &state) {
  return !CondGE(state);
}

static inline bool CondEQ(const State &state) {
  return UCmpNeq(state.state.Z, 0);
}

static inline bool CondGT(const State &state) {
  return CondGE(state) && !CondEQ(state);
}

static inline bool CondLE(const State &state) {
  return CondLT(state) || CondEQ(state);
}

static inline bool CondCS(const State &state) {
  return UCmpNeq(state.state.C, 0);
}

static inline bool CondMI(const State &state) {
  return UCmpNeq(state.state.N, 0);
}

static inline bool CondVS(const State &state) {
  return UCmpNeq(state.state.V, 0);
}

static inline bool CondHI(const State &state) {
  return CondCS(state) && !CondEQ(state);
}

template <bool (*check_cond)(const State &)>
static bool NotCond(const State &state) {
  return !check_cond(state);
}

}  // namespace

DEF_COND(GE) = CondGE;
DEF_COND(GT) = CondGT;
DEF_COND(LE) = CondLE;
DEF_COND(LT) = CondLT;

DEF_COND(EQ) = CondEQ;
DEF_COND(NE) = NotCond<CondEQ>;

DEF_COND(CS) = CondCS;
DEF_COND(CC) = NotCond<CondCS>;

DEF_COND(MI) = CondMI;
DEF_COND(PL) = NotCond<CondMI>;

DEF_COND(VS) = CondVS;
DEF_COND(VC) = NotCond<CondVS>;

DEF_COND(HI) = CondHI;
DEF_COND(LS) = NotCond<CondHI>;

namespace {

DEF_SEM(DoDirectBranch, PC target_pc) {
  Write(REG_PC, Read(target_pc));
  return memory;
}

DEF_SEM(DoIndirectBranch, PC dst) {
  Write(REG_PC, Read(dst));
  return memory;
}

template <bool (*check_cond)(const State &)>
DEF_SEM(DirectCondBranch, R8W cond, PC taken, PC not_taken) {
  addr_t taken_pc = Read(taken);
  addr_t not_taken_pc = Read(not_taken);
  uint8_t take_branch = check_cond(state);
  Write(cond, take_branch);
  Write(REG_PC, Select<addr_t>(take_branch, taken_pc, not_taken_pc));
  return memory;
}

template <typename S>
DEF_SEM(CBZ, R8W cond, S src, PC taken, PC not_taken) {
  addr_t taken_pc = Read(taken);
  addr_t not_taken_pc = Read(not_taken);
  uint8_t take_branch = UCmpEq(Read(src), 0);
  Write(cond, take_branch);
  Write(REG_PC, Select<addr_t>(take_branch, taken_pc, not_taken_pc));
  return memory;
}

template <typename S>
DEF_SEM(CBNZ, R8W cond, S src, PC taken, PC not_taken) {
  addr_t taken_pc = Read(taken);
  addr_t not_taken_pc = Read(not_taken);
  uint8_t take_branch = UCmpNeq(Read(src), 0);
  Write(cond, take_branch);
  Write(REG_PC, Select<addr_t>(take_branch, taken_pc, not_taken_pc));
  return memory;
}

}  // namespace

DEF_ISEL(B_U) = DoDirectBranch;

DEF_ISEL(B_LS_R8W_U_U) = DirectCondBranch<NotCond<CondHI>>;

DEF_ISEL(B_EQ_R8W_U_U) = DirectCondBranch<CondEQ>;
DEF_ISEL(B_NE_R8W_U_U) = DirectCondBranch<NotCond<CondEQ>>;

DEF_ISEL(B_GE_R8W_U_U) = DirectCondBranch<CondGE>;
DEF_ISEL(B_GT_R8W_U_U) = DirectCondBranch<CondGT>;

DEF_ISEL(B_LE_R8W_U_U) = DirectCondBranch<CondLE>;
DEF_ISEL(B_LT_R8W_U_U) = DirectCondBranch<CondLT>;

DEF_ISEL(BR_R64) = DoIndirectBranch;

DEF_ISEL(CBZ_R8W_R64_U_U) = CBZ<R64>;
DEF_ISEL(CBZ_R8W_R32_U_U) = CBZ<R32>;

DEF_ISEL(CBNZ_R8W_R64_U_U) = CBNZ<R64>;
DEF_ISEL(CBNZ_R8W_R32_U_U) = CBNZ<R32>;
