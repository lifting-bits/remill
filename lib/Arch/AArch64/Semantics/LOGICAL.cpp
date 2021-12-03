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
DEF_SEM(ORN, D dst, S1 src1, S2 src2) {
  WriteZExt(dst, UOr(Read(src1), UNot(Read(src2))));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(EOR, D dst, S1 src1, S2 src2) {
  WriteZExt(dst, UXor(Read(src1), Read(src2)));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(EON, D dst, S1 src1, S2 src2) {
  WriteZExt(dst, UXor(Read(src1), UNot(Read(src2))));
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

template <typename D, typename S1, typename S2>
DEF_SEM(BICS, D dst, S1 src1, S2 src2) {
  auto res = UAnd(Read(src1), UNot(Read(src2)));
  WriteZExt(dst, res);
  FLAG_N = SignFlag(res, src1, src2);
  FLAG_Z = ZeroFlag(res, src1, src2);
  FLAG_C = false;
  FLAG_V = false;
  return memory;
}

}  // namespace


DEF_ISEL(ORN_32_LOG_SHIFT) = ORN<R32W, R32, I32>;
DEF_ISEL(ORN_64_LOG_SHIFT) = ORN<R64W, R64, I64>;

DEF_ISEL(EOR_32_LOG_SHIFT) = EOR<R32W, R32, I32>;
DEF_ISEL(EOR_64_LOG_SHIFT) = EOR<R64W, R64, I64>;
DEF_ISEL(EOR_32_LOG_IMM) = EOR<R32W, R32, I32>;
DEF_ISEL(EOR_64_LOG_IMM) = EOR<R64W, R64, I64>;

DEF_ISEL(EON_32_LOG_SHIFT) = EON<R32W, R32, I32>;
DEF_ISEL(EON_64_LOG_SHIFT) = EON<R64W, R64, I64>;

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

DEF_ISEL(BICS_32_LOG_SHIFT) = BICS<R32W, R32, I32>;
DEF_ISEL(BICS_64_LOG_SHIFT) = BICS<R64W, R64, I64>;

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(ANDS, D dst, S1 src1, S2 src2) {
  auto res = UAnd(Read(src1), Read(src2));
  WriteZExt(dst, res);
  FLAG_N = SignFlag(res, src1, src2);
  FLAG_Z = ZeroFlag(res, src1, src2);
  FLAG_C = false;
  FLAG_V = false;
  return memory;
}

}  // namespace

DEF_ISEL(ANDS_32S_LOG_IMM) = ANDS<R32W, R32, I32>;
DEF_ISEL(ANDS_64S_LOG_IMM) = ANDS<R64W, R64, I64>;

DEF_ISEL(ANDS_32_LOG_SHIFT) = ANDS<R32W, R32, I32>;
DEF_ISEL(ANDS_64_LOG_SHIFT) = ANDS<R64W, R64, I64>;

namespace {

template <typename D, typename S>
DEF_SEM(LSLV, D dst, S src1, S src2) {
  using T = typename BaseType<S>::BT;
  constexpr auto size = T(sizeof(T) * 8);
  WriteZExt(dst, UShl(Read(src1), URem(Read(src2), size)));
  return memory;
}

template <typename D, typename S>
DEF_SEM(LSRV, D dst, S src1, S src2) {
  using T = typename BaseType<S>::BT;
  constexpr auto size = T(sizeof(T) * 8);
  WriteZExt(dst, UShr(Read(src1), URem(Read(src2), size)));
  return memory;
}

template <typename D, typename S>
DEF_SEM(ASRV, D dst, S src1, S src2) {
  using T = typename BaseType<S>::BT;
  constexpr auto size = T(sizeof(T) * 8);
  WriteZExt(dst,
            Unsigned(SShr(Signed(Read(src1)), Signed(URem(Read(src2), size)))));
  return memory;
}

template <typename D, typename S>
DEF_SEM(RORV, D dst, S src1, S src2) {
  using T = typename BaseType<S>::BT;
  constexpr auto size = T(sizeof(T) * 8);
  WriteZExt(dst, Ror(Read(src1), URem(Read(src2), size)));
  return memory;
}
}  // namespace

DEF_ISEL(LSLV_32_DP_2SRC) = LSLV<R32W, R32>;
DEF_ISEL(LSLV_64_DP_2SRC) = LSLV<R64W, R64>;

DEF_ISEL(LSRV_32_DP_2SRC) = LSRV<R32W, R32>;
DEF_ISEL(LSRV_64_DP_2SRC) = LSRV<R64W, R64>;

DEF_ISEL(ASRV_32_DP_2SRC) = ASRV<R32W, R32>;
DEF_ISEL(ASRV_64_DP_2SRC) = ASRV<R64W, R64>;

DEF_ISEL(RORV_32_DP_2SRC) = RORV<R32W, R32>;
DEF_ISEL(RORV_64_DP_2SRC) = RORV<R64W, R64>;
