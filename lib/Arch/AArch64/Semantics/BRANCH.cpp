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

// when '101' result = (PSTATE.N == PSTATE.V); // GE or LT
static inline bool CondGE(const State &state) {
  return __remill_compare_sge(FLAG_N == FLAG_V);
}

// when '101' result = (PSTATE.N == PSTATE.V); // GE or LT
static inline bool CondLT(const State &state) {
  return __remill_compare_slt(FLAG_N != FLAG_V);
}

// when '000' result = (PSTATE.Z == '1'); // EQ or NE
static inline bool CondEQ(const State &state) {
  return __remill_compare_eq(FLAG_Z);
}

// when '000' result = (PSTATE.Z == '1'); // EQ or NE
static inline bool CondNE(const State &state) {
  return __remill_compare_neq(!FLAG_Z);
}

// when '110' result = (PSTATE.N == PSTATE.V && PSTATE.Z == '0'); // GT or LE
static inline bool CondGT(const State &state) {
  return __remill_compare_sgt((FLAG_N == FLAG_V) && !FLAG_Z);
}

// when '110' result = (PSTATE.N == PSTATE.V && PSTATE.Z == '0'); // GT or LE
static inline bool CondLE(const State &state) {
  return __remill_compare_sle((FLAG_N != FLAG_V) || FLAG_Z);
}

// when '001' result = (PSTATE.C == '1'); // CS or CC
static inline bool CondCS(const State &state) {
  return __remill_compare_uge(FLAG_C);
}

// when '001' result = (PSTATE.C == '1'); // CS or CC
static inline bool CondCC(const State &state) {
  return __remill_compare_ult(!FLAG_C);
}

// when '010' result = (PSTATE.N == '1'); // MI or PL
static inline bool CondMI(const State &state) {
  return FLAG_N;
}

// when '010' result = (PSTATE.N == '1'); // MI or PL
static inline bool CondPL(const State &state) {
  return !FLAG_N;
}

// when '011' result = (PSTATE.V == '1'); // VS or VC
static inline bool CondVS(const State &state) {
  return FLAG_V;
}

// when '011' result = (PSTATE.V == '1'); // VS or VC
static inline bool CondVC(const State &state) {
  return !FLAG_V;
}

// when '100' result = (PSTATE.C == '1' && PSTATE.Z == '0'); // HI or LS
static inline bool CondHI(const State &state) {
  return __remill_compare_ugt(FLAG_C && !FLAG_Z);
}

// when '100' result = (PSTATE.C == '1' && PSTATE.Z == '0'); // HI or LS
static inline bool CondLS(const State &state) {
  return __remill_compare_ule(!FLAG_C || FLAG_Z);
}

static inline bool CondAL(const State &state) {
  return true;
}

}  // namespace

DEF_COND(GE) = CondGE;
DEF_COND(GT) = CondGT;

DEF_COND(LE) = CondLE;
DEF_COND(LT) = CondLT;

DEF_COND(EQ) = CondEQ;
DEF_COND(NE) = CondNE;

DEF_COND(CS) = CondCS;
DEF_COND(CC) = CondCC;

DEF_COND(MI) = CondMI;
DEF_COND(PL) = CondPL;

DEF_COND(VS) = CondVS;
DEF_COND(VC) = CondVC;

DEF_COND(HI) = CondHI;
DEF_COND(LS) = CondLS;

DEF_COND(AL) = CondAL;

namespace {

DEF_SEM(DoDirectBranch, PC target_pc, R64W pc_dst) {
  const auto new_pc = Read(target_pc);
  Write(REG_PC, new_pc);
  Write(pc_dst, new_pc);
  return memory;
}

template <typename S>
DEF_SEM(DoIndirectBranch, S dst, R64W pc_dst) {
  const auto new_pc = Read(dst);
  Write(REG_PC, new_pc);
  Write(pc_dst, new_pc);
  return memory;
}

template <bool (*check_cond)(const State &)>
DEF_SEM(DirectCondBranch, R8W cond, PC taken, PC not_taken, R64W pc_dst) {
  addr_t taken_pc = Read(taken);
  addr_t not_taken_pc = Read(not_taken);
  uint8_t take_branch = check_cond(state);
  Write(cond, take_branch);

  const auto new_pc = Select<addr_t>(take_branch, taken_pc, not_taken_pc);
  Write(REG_PC, new_pc);
  Write(pc_dst, new_pc);
  return memory;
}

template <typename S>
DEF_SEM(CBZ, R8W cond, PC taken, PC not_taken, S src, R64W pc_dst) {
  addr_t taken_pc = Read(taken);
  addr_t not_taken_pc = Read(not_taken);
  uint8_t take_branch = UCmpEq(Read(src), 0);
  Write(cond, take_branch);

  const auto new_pc = Select<addr_t>(take_branch, taken_pc, not_taken_pc);
  Write(REG_PC, new_pc);
  Write(pc_dst, new_pc);
  return memory;
}

template <typename S>
DEF_SEM(CBNZ, R8W cond, PC taken, PC not_taken, S src, R64W pc_dst) {
  addr_t taken_pc = Read(taken);
  addr_t not_taken_pc = Read(not_taken);
  uint8_t take_branch = UCmpNeq(Read(src), 0);
  Write(cond, take_branch);

  const auto new_pc = Select<addr_t>(take_branch, taken_pc, not_taken_pc);
  Write(REG_PC, new_pc);
  Write(pc_dst, new_pc);
  return memory;
}


template <typename S>
DEF_SEM(TBZ, I8 bit_pos, R8W cond, PC taken, PC not_taken, S src, R64W pc_dst) {
  addr_t taken_pc = Read(taken);
  addr_t not_taken_pc = Read(not_taken);
  auto bit_n = ZExtTo<S>(Read(bit_pos));
  auto reg_val = ZExtTo<S>(Read(src));
  auto bit_set = UAnd(reg_val, UShl(ZExtTo<S>(1), bit_n));
  auto take_branch = UCmpEq(bit_set, 0);
  Write(cond, take_branch);

  const auto new_pc = Select<addr_t>(take_branch, taken_pc, not_taken_pc);
  Write(REG_PC, new_pc);
  Write(pc_dst, new_pc);
  return memory;
}

template <typename S>
DEF_SEM(TBNZ, I8 bit_pos, R8W cond, PC taken, PC not_taken, S src,
        R64W pc_dst) {
  addr_t taken_pc = Read(taken);
  addr_t not_taken_pc = Read(not_taken);
  auto bit_n = ZExtTo<S>(Read(bit_pos));
  auto reg_val = ZExtTo<S>(Read(src));
  auto bit_set = UAnd(reg_val, UShl(ZExtTo<S>(1), bit_n));
  auto take_branch = UCmpNeq(bit_set, 0);
  Write(cond, take_branch);

  const auto new_pc = Select<addr_t>(take_branch, taken_pc, not_taken_pc);
  Write(REG_PC, new_pc);
  Write(pc_dst, new_pc);
  return memory;
}

}  // namespace

DEF_ISEL(BR_64_BRANCH_REG) = DoIndirectBranch<R64>;

DEF_ISEL(B_ONLY_BRANCH_IMM) = DoDirectBranch;

DEF_ISEL(B_ONLY_CONDBRANCH_EQ) = DirectCondBranch<CondEQ>;
DEF_ISEL(B_ONLY_CONDBRANCH_NE) = DirectCondBranch<CondNE>;
DEF_ISEL(B_ONLY_CONDBRANCH_CS) = DirectCondBranch<CondCS>;
DEF_ISEL(B_ONLY_CONDBRANCH_CC) = DirectCondBranch<CondCC>;
DEF_ISEL(B_ONLY_CONDBRANCH_MI) = DirectCondBranch<CondMI>;
DEF_ISEL(B_ONLY_CONDBRANCH_PL) = DirectCondBranch<CondPL>;
DEF_ISEL(B_ONLY_CONDBRANCH_VS) = DirectCondBranch<CondVS>;
DEF_ISEL(B_ONLY_CONDBRANCH_VC) = DirectCondBranch<CondVC>;
DEF_ISEL(B_ONLY_CONDBRANCH_HI) = DirectCondBranch<CondHI>;
DEF_ISEL(B_ONLY_CONDBRANCH_LS) = DirectCondBranch<CondLS>;
DEF_ISEL(B_ONLY_CONDBRANCH_GE) = DirectCondBranch<CondGE>;
DEF_ISEL(B_ONLY_CONDBRANCH_LT) = DirectCondBranch<CondLT>;
DEF_ISEL(B_ONLY_CONDBRANCH_GT) = DirectCondBranch<CondGT>;
DEF_ISEL(B_ONLY_CONDBRANCH_LE) = DirectCondBranch<CondLE>;
DEF_ISEL(B_ONLY_CONDBRANCH_AL) = DirectCondBranch<CondAL>;

DEF_ISEL(CBZ_64_COMPBRANCH) = CBZ<R64>;
DEF_ISEL(CBZ_32_COMPBRANCH) = CBZ<R32>;

DEF_ISEL(CBNZ_64_COMPBRANCH) = CBNZ<R64>;
DEF_ISEL(CBNZ_32_COMPBRANCH) = CBNZ<R32>;

DEF_ISEL(TBZ_ONLY_TESTBRANCH_64) = TBZ<R64>;
DEF_ISEL(TBZ_ONLY_TESTBRANCH_32) = TBZ<R32>;
DEF_ISEL(TBNZ_ONLY_TESTBRANCH_64) = TBNZ<R64>;
DEF_ISEL(TBNZ_ONLY_TESTBRANCH_32) = TBNZ<R32>;
