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

template <typename T>
T AddWithCarryNZCV(State &state, T lhs, T rhs, T carry) {
  auto unsigned_result = UAdd(UAdd(ZExt(lhs), ZExt(rhs)), ZExt(carry));
  auto signed_result = SAdd(SAdd(SExt(lhs), SExt(rhs)), Signed(ZExt(carry)));
  auto result = TruncTo<T>(unsigned_result);
  state.sr.n = SignFlag(result);
  state.sr.z = ZeroFlag(result);
  state.sr.c = UCmpNeq(ZExt(result), unsigned_result);
  state.sr.v = SCmpNeq(SExt(result), signed_result);
  return result;
}



template <typename D, typename S1, typename S2>
DEF_SEM(AND, D dst, S1 src1, S2 src2) {
  Write(dst, UAnd(Read(src1), Read(src2)));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(ANDS, D dst, S1 src1, S2 src2) {
  auto res = UAnd(Read(src1), Read(src2));
  WriteZExt(dst, res);
  state.sr.n = SignFlag(res);
  state.sr.z = ZeroFlag(res);
  state.sr.c = false;
  // PSTATE.V unchanged
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(EOR, D dst, S1 src1, S2 src2) {
  Write(dst, UXor(Read(src1), Read(src2)));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(RSB, D dst, S1 src1, S2 src2) {
  Write(dst, USub(Read(src2), Read(src1)));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(SUB, D dst, S1 src1, S2 src2) {
  Write(dst, USub(Read(src1), Read(src2)));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(ADD, D dst, S1 src1, S2 src2) {
  Write(dst, UAdd(Read(src1), Read(src2)));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(ADDS, D dst, S1 src1, S2 src2) {
  using T = typename BaseType<S2>::BT;
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = AddWithCarryNZCV(state, lhs, rhs, T(0));
  Write(dst, res);
  return memory;
}


template <typename D, typename S1, typename S2>
DEF_SEM(ADC, D dst, S1 src1, S2 src2) {
  Write(dst, UAdd(UAdd(Read(src1), Read(src2)), ZExtTo<S1>(state.sr.c)));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(SBC, D dst, S1 src1, S2 src2) {
  Write(dst, UAdd(UAdd(Read(src1), UNot(Read(src2))), ZExtTo<S1>(state.sr.c)));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(RSC, D dst, S1 src1, S2 src2) {
  Write(dst, UAdd(UAdd(Read(src2), UNot(Read(src1))), ZExtTo<S1>(state.sr.c)));
  return memory;
}

}  // namespace

DEF_ISEL(ANDrr) = AND<R32W, R32, I32>;
DEF_ISEL(EORrr) = EOR<R32W, R32, I32>;
DEF_ISEL(ADDrr) = ADD<R32W, R32, I32>;
DEF_ISEL(ADDSrr) = ADDS<R32W, R32, I32>;
DEF_ISEL(ADCrr) = ADC<R32W, R32, I32>;
DEF_ISEL(RSBrr) = RSB<R32W, R32, I32>;
DEF_ISEL(SUBrr) = SUB<R32W, R32, I32>;
DEF_ISEL(SBCrr) = SBC<R32W, R32, I32>;
DEF_ISEL(RSCrr) = RSC<R32W, R32, I32>;
