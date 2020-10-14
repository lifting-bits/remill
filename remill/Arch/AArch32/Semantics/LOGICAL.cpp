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

DEF_SEM(ORR, R32W dst, R32 src1, I32 src2, I32 src2_rrx){
  auto value = UOr(Read(src2), Read(src2_rrx));
  auto result = UOr(Read(src1), value);
  Write(dst, result);
  return memory;
}

DEF_SEM(ORRS, R32W dst, R32 src1, I32 src2, I32 src2_rrx, I8 carry_out) {
  auto value = UOr(Read(src2), Read(src2_rrx));
  auto result = UOr(Read(src1), value);
  Write(dst, result);

  state.sr.n = SignFlag(result);
  state.sr.z = ZeroFlag(result);
  state.sr.c = Read(carry_out);
  // PSTATE.V unchanged
  return memory;
}

DEF_SEM(BIC, R32W dst, R32 src1, I32 src2, I32 src2_rrx){
  auto value = UNot(UOr(Read(src2), Read(src2_rrx)));
  auto result = UAnd(Read(src1), value);
  Write(dst, result);
  return memory;
}

DEF_SEM(BICS, R32W dst, R32 src1, I32 src2, I32 src2_rrx, I8 carry_out) {
  auto value = UNot(UOr(Read(src2), Read(src2_rrx)));
  auto result = UAnd(Read(src1), value);
  Write(dst, result);

  state.sr.n = SignFlag(result);
  state.sr.z = ZeroFlag(result);
  state.sr.c = Read(carry_out);
  // PSTATE.V unchanged
  return memory;
}

} // namespace

DEF_ISEL(ORRrrri) = ORR;
DEF_ISEL(ORRSrrri) = ORRS;
DEF_ISEL(MOVrrri) = ORR;
DEF_ISEL(MOVSrrri) = ORRS;
DEF_ISEL(BICrrri) = BIC;
DEF_ISEL(BICSrrri) = BICS;
DEF_ISEL(MVNrrri) = BIC;
DEF_ISEL(MVNSrrri) = BICS;
