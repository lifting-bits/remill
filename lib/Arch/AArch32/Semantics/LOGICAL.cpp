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
DEF_COND_SEM(ORR, R32W dst, R32 src1, I32 src2, R32W maybe_next_pc_dst) {
  auto value = Read(src2);
  auto result = UOr(Read(src1), value);
  Write(dst, result);
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(ORRS, R32W dst, R32 src1, I32 src2, I8 carry_out,
             R32W maybe_next_pc_dst) {
  auto value = Read(src2);
  auto result = UOr(Read(src1), value);
  Write(dst, result);

  state.sr.n = SignFlag(result);
  state.sr.z = ZeroFlag(result);
  state.sr.c = Read(carry_out);

  // PSTATE.V unchanged

  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(BIC, R32W dst, R32 src1, I32 src2, R32W maybe_next_pc_dst) {
  auto value = UNot(Read(src2));
  auto result = UAnd(Read(src1), value);
  Write(dst, result);
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(BICS, R32W dst, R32 src1, I32 src2, I8 carry_out,
             R32W maybe_next_pc_dst) {
  auto value = UNot(Read(src2));
  auto result = UAnd(Read(src1), value);
  Write(dst, result);

  state.sr.n = SignFlag(result);
  state.sr.z = ZeroFlag(result);
  state.sr.c = Read(carry_out);

  // PSTATE.V unchanged
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

}  // namespace

DEF_ISEL(ORRrr) = ORR;
DEF_ISEL(ORRSrr) = ORRS;
DEF_ISEL(MOVrr) = ORR;
DEF_ISEL(MOVSrr) = ORRS;
DEF_ISEL(BICrr) = BIC;
DEF_ISEL(BICSrr) = BICS;
DEF_ISEL(MVNrr) = BIC;
DEF_ISEL(MVNSrr) = BICS;

DEF_ISEL(MOVW) = ORR;

namespace {
DEF_COND_SEM(MOVT, R32W dst, R32 src1, R32 src2) {
  auto value = ZExt(Trunc(Read(src1)));
  auto result = UOr(UShl(Read(src2), 16), value);
  Write(dst, result);
  return memory;
}
}  // namespace

DEF_ISEL(MOVT) = MOVT;
