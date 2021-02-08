/*
 * Copyright (c) 2020 Trail of Bits, Inc.
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
DEF_COND_SEM(TST, R32 src1, I32 src2, I8 carry_out) {
  auto res = UAnd(Read(src1), Read(src2));

  state.sr.n = SignFlag(res);
  state.sr.z = ZeroFlag(res);
  state.sr.c = Read(carry_out);

  // PSTATE.V unchanged
  return memory;
}

DEF_COND_SEM(TEQ, R32 src1, I32 src2, I8 carry_out) {
  auto res = UXor(Read(src1), Read(src2));

  state.sr.n = SignFlag(res);
  state.sr.z = ZeroFlag(res);
  state.sr.c = Read(carry_out);

  // PSTATE.V unchanged
  return memory;
}

DEF_COND_SEM(CMP, R32 src1, I32 src2, I8 carry_out) {
  auto rhs = Read(src2);
  auto lhs = Read(src1);
  AddWithCarryNZCV(state, lhs, UNot(rhs), uint32_t(1));
  return memory;
}

DEF_COND_SEM(CMN, R32 src1, I32 src2, I8 carry_out) {
  auto rhs = Read(src2);
  auto lhs = Read(src1);
  AddWithCarryNZCV(state, lhs, rhs, uint32_t(0));
  return memory;
}
}  // namespace

DEF_ISEL(TSTr) = TST;
DEF_ISEL(TEQr) = TEQ;
DEF_ISEL(CMPr) = CMP;
DEF_ISEL(CMNr) = CMN;
