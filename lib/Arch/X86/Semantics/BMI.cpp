/*
* Copyright (c) 2025 Trail of Bits, Inc.
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
ALWAYS_INLINE void SetFlagsBMI(State &state, T lhs, T rhs, T res) {
  state.aflag.cf = false;
  state.aflag.pf = __remill_undefined_8();
  state.aflag.zf = ZeroFlag(res, lhs, rhs);
  state.aflag.sf = SignFlag(res, lhs, rhs);
  state.aflag.of = false;
  state.aflag.af = __remill_undefined_8();
}

template <typename D, typename S1, typename S2>
DEF_SEM(ANDN, D dst, S1 src1, S2 src2) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto res = UAnd(UNot(lhs), rhs);
  WriteZExt(dst, res);
  SetFlagsBMI(state, lhs, rhs, res);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(BEXTR, D dst, S1 src1, S2 src2) {
  auto source = Read(src1);
  auto control = Read(src2);

  // Extract start position from bits [7:0]
  auto start = ZExtTo<S1>(UAnd(control, Literal<S2>(0xFF)));
  // Extract length from bits [15:8]
  auto length = ZExtTo<S1>(UAnd(UShr(control, Literal<S2>(8)), Literal<S2>(0xFF)));

  // Constrain start and length to operand size to avoid undefined behavior
  start = URem(start, BitSizeOf(src1));
  length = URem(length, BitSizeOf(src1));

  // Extract bits: (source >> start) & ((1 << length) - 1)
  auto shifted = UShr(source, start);
  auto mask = USub(UShl(Literal<S1>(1), length), Literal<S1>(1));
  auto result = UAnd(shifted, mask);

  WriteZExt(dst, result);

  // Set flags according to Intel specification
  Write(FLAG_ZF, ZeroFlag(result, source, control));
  Write(FLAG_OF, false);
  Write(FLAG_CF, false);
  Write(FLAG_AF, __remill_undefined_8());
  Write(FLAG_SF, __remill_undefined_8());
  Write(FLAG_PF, __remill_undefined_8());

  return memory;
}

template <typename D, typename S>
DEF_SEM(BLSI, D dst, S src) {
  auto val = Read(src);
  auto res = UAnd(UNeg(val), val);
  WriteZExt(dst, res);
  SetFlagsBMI(state, val, val, res);
  Write(FLAG_CF, ZeroFlag(res, val, val));
  return memory;
}

template <typename D, typename S>
DEF_SEM(BLSMSK, D dst, S src) {
  auto val = Read(src);
  auto res = UXor(USub(val, Literal<S>(1)), val);
  WriteZExt(dst, res);
  SetFlagsBMI(state, val, val, res);
  Write(FLAG_CF, UCmpEq(val, 0));
  Write(FLAG_ZF, false);
  return memory;
}

template <typename D, typename S>
DEF_SEM(BLSR, D dst, S src) {
  auto val = Read(src);
  auto res = UAnd(USub(val, Literal<S>(1)), val);
  WriteZExt(dst, res);
  SetFlagsBMI(state, val, val, res);
  Write(FLAG_CF, UCmpEq(val, 0));
  return memory;
}

template <typename D, typename S>
DEF_SEM(TZCNT, D dst, S src) {
  auto val = Read(src);
  auto count = CountTrailingZeros(val);
  ClearArithFlags();
  Write(FLAG_ZF, UCmpEq(UAnd(val, Literal<S>(1)), 1));
  Write(FLAG_CF, ZeroFlag(val));
  WriteZExt(dst, Select(FLAG_CF, BitSizeOf(src), count));
  return memory;
}

DEF_ISEL(ANDN_GPRv_GPRv_GPRv_32) = ANDN<R32W, R32, R32>;
DEF_ISEL(ANDN_GPRv_GPRv_MEMv_32) = ANDN<R32W, R32, M32>;
IF_64BIT(DEF_ISEL(ANDN_GPRv_GPRv_GPRv_64) = ANDN<R64W, R64, R64>;)
IF_64BIT(DEF_ISEL(ANDN_GPRv_GPRv_MEMv_64) = ANDN<R64W, R64, M64>;)

DEF_ISEL(BEXTR_VGPR32d_VGPR32d_VGPR32d) = BEXTR<R32W, R32, R32>;
DEF_ISEL(BEXTR_VGPR32d_MEMd_VGPR32d) = BEXTR<R32W, M32, R32>;
IF_64BIT(DEF_ISEL(BEXTR_VGPR64q_VGPR64q_VGPR64q) = BEXTR<R64W, R64, R64>;)
IF_64BIT(DEF_ISEL(BEXTR_VGPR64q_MEMq_VGPR64q) = BEXTR<R64W, M64, R64>;)

DEF_ISEL(BLSI_GPRv_GPRv_32) = BLSI<R32W, R32>;
DEF_ISEL(BLSI_GPRv_MEMv_32) = BLSI<R32W, M32>;
IF_64BIT(DEF_ISEL(BLSI_GPRv_GPRv_64) = BLSI<R64W, R64>;)
IF_64BIT(DEF_ISEL(BLSI_GPRv_MEMv_64) = BLSI<R64W, M64>;)

DEF_ISEL(BLSMSK_GPRv_GPRv_32) = BLSMSK<R32W, R32>;
DEF_ISEL(BLSMSK_GPRv_MEMv_32) = BLSMSK<R32W, M32>;
IF_64BIT(DEF_ISEL(BLSMSK_GPRv_GPRv_64) = BLSMSK<R64W, R64>;)
IF_64BIT(DEF_ISEL(BLSMSK_GPRv_MEMv_64) = BLSMSK<R64W, M64>;)

DEF_ISEL(BLSR_GPRv_GPRv_32) = BLSR<R32W, R32>;
DEF_ISEL(BLSR_GPRv_MEMv_32) = BLSR<R32W, M32>;
IF_64BIT(DEF_ISEL(BLSR_GPRv_GPRv_64) = BLSR<R64W, R64>;)
IF_64BIT(DEF_ISEL(BLSR_GPRv_MEMv_64) = BLSR<R64W, M64>;)

DEF_ISEL(TZCNT_GPRv_GPRv_16) = TZCNT<R16W, R16>;
DEF_ISEL(TZCNT_GPRv_MEMv_16) = TZCNT<R16W, M16>;
DEF_ISEL(TZCNT_GPRv_GPRv_32) = TZCNT<R32W, R32>;
DEF_ISEL(TZCNT_GPRv_GPRv_32) = TZCNT<R32W, M32>;
IF_64BIT(DEF_ISEL(TZCNT_GPRv_GPRv_64) = TZCNT<R64W, R64>;)
IF_64BIT(DEF_ISEL(TZCNT_GPRv_MEMv_64) = TZCNT<R64W, M64>;)
