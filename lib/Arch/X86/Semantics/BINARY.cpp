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

#pragma once

namespace {

template <typename Tag, typename T>
ALWAYS_INLINE static void WriteFlagsIncDec(State &state, T lhs, T rhs, T res) {
  FLAG_PF = ParityFlag(res);
  FLAG_AF = AuxCarryFlag(lhs, rhs, res);
  FLAG_ZF = ZeroFlag(res, lhs, rhs);
  FLAG_SF = SignFlag(res, lhs, rhs);
  FLAG_OF = Overflow<Tag>::Flag(lhs, rhs, res);
}

template <typename Tag, typename T>
ALWAYS_INLINE static void WriteFlagsAddSub(State &state, T lhs, T rhs, T res) {
  FLAG_CF = Carry<Tag>::Flag(lhs, rhs, res);
  WriteFlagsIncDec<Tag>(state, lhs, rhs, res);
}

template <typename D, typename S1, typename S2>
DEF_SEM(ADD, D dst, S1 src1, S2 src2) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto sum = UAdd(lhs, rhs);
  WriteZExt(dst, sum);
  WriteFlagsAddSub<tag_add>(state, lhs, rhs, sum);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(ADDPS, D dst, S1 src1, S2 src2) {
  FWriteV32(dst, FAddV32(FReadV32(src1), FReadV32(src2)));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(ADDPD, D dst, S1 src1, S2 src2) {
  FWriteV64(dst, FAddV64(FReadV64(src1), FReadV64(src2)));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(ADDSS, D dst, S1 src1, S2 src2) {
  auto lhs = FReadV32(src1);
  auto rhs = FReadV32(src2);
  auto sum = FAdd(FExtractV32(lhs, 0), FExtractV32(rhs, 0));
  auto res = FInsertV32(lhs, 0, sum);
  FWriteV32(dst, res);  // SSE: Writes to XMM, AVX: Zero-extends XMM.
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(ADDSD, D dst, S1 src1, S2 src2) {
  auto lhs = FReadV64(src1);
  auto rhs = FReadV64(src2);
  auto sum = FAdd(FExtractV64(lhs, 0), FExtractV64(rhs, 0));
  auto res = FInsertV64(lhs, 0, sum);
  FWriteV64(dst, res);  // SSE: Writes to XMM, AVX: Zero-extends XMM.
  return memory;
}

}  // namespace

DEF_ISEL(ADD_MEMb_IMMb_80r0) = ADD<M8W, M8, I8>;
DEF_ISEL(ADD_GPR8_IMMb_80r0) = ADD<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(ADD_MEMv_IMMz, ADD);
DEF_ISEL_RnW_Rn_In(ADD_GPRv_IMMz, ADD);
DEF_ISEL(ADD_MEMb_IMMb_82r0) = ADD<M8W, M8, I8>;
DEF_ISEL(ADD_GPR8_IMMb_82r0) = ADD<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(ADD_MEMv_IMMb, ADD);
DEF_ISEL_RnW_Rn_In(ADD_GPRv_IMMb, ADD);
DEF_ISEL(ADD_MEMb_GPR8) = ADD<M8W, M8, R8>;
DEF_ISEL(ADD_GPR8_GPR8_00) = ADD<R8W, R8, R8>;
DEF_ISEL_MnW_Mn_Rn(ADD_MEMv_GPRv, ADD);
DEF_ISEL_RnW_Rn_Rn(ADD_GPRv_GPRv_01, ADD);
DEF_ISEL(ADD_GPR8_MEMb) = ADD<R8W, R8, M8>;
DEF_ISEL(ADD_GPR8_GPR8_02) = ADD<R8W, R8, R8>;
DEF_ISEL_RnW_Rn_Mn(ADD_GPRv_MEMv, ADD);
DEF_ISEL_RnW_Rn_Rn(ADD_GPRv_GPRv_03, ADD);
DEF_ISEL(ADD_AL_IMMb) = ADD<R8W, R8, I8>;
DEF_ISEL_RnW_Rn_In(ADD_OrAX_IMMz, ADD);

DEF_ISEL(ADDPS_XMMps_MEMps) = ADDPS<V128W, V128, MV128>;
DEF_ISEL(ADDPS_XMMps_XMMps) = ADDPS<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VADDPS_XMMdq_XMMdq_MEMdq) = ADDPS<VV128W, VV128, MV128>;)
IF_AVX(DEF_ISEL(VADDPS_XMMdq_XMMdq_XMMdq) = ADDPS<VV128W, VV128, VV128>;)
IF_AVX(DEF_ISEL(VADDPS_YMMqq_YMMqq_MEMqq) = ADDPS<VV256W, VV256, MV256>;)
IF_AVX(DEF_ISEL(VADDPS_YMMqq_YMMqq_YMMqq) = ADDPS<VV256W, VV256, VV256>;)

DEF_ISEL(ADDPD_XMMpd_MEMpd) = ADDPD<V128W, V128, MV128>;
DEF_ISEL(ADDPD_XMMpd_XMMpd) = ADDPD<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VADDPD_XMMdq_XMMdq_MEMdq) = ADDPD<VV128W, VV128, MV128>;)
IF_AVX(DEF_ISEL(VADDPD_XMMdq_XMMdq_XMMdq) = ADDPD<VV128W, VV128, VV128>;)
IF_AVX(DEF_ISEL(VADDPD_YMMqq_YMMqq_MEMqq) = ADDPD<VV256W, VV256, MV256>;)
IF_AVX(DEF_ISEL(VADDPD_YMMqq_YMMqq_YMMqq) = ADDPD<VV256W, VV256, VV256>;)

DEF_ISEL(ADDSS_XMMss_MEMss) = ADDSS<V128W, V128, MV32>;
DEF_ISEL(ADDSS_XMMss_XMMss) = ADDSS<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VADDSS_XMMdq_XMMdq_MEMd) = ADDSS<VV128W, VV128, MV32>;)
IF_AVX(DEF_ISEL(VADDSS_XMMdq_XMMdq_XMMd) = ADDSS<VV128W, VV128, VV128>;)

DEF_ISEL(ADDSD_XMMsd_MEMsd) = ADDSD<V128W, V128, MV64>;
DEF_ISEL(ADDSD_XMMsd_XMMsd) = ADDSD<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VADDSD_XMMdq_XMMdq_MEMq) = ADDSD<VV128W, VV128, MV64>;)
IF_AVX(DEF_ISEL(VADDSD_XMMdq_XMMdq_XMMq) = ADDSD<VV128W, VV128, VV128>;)

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(SUB, D dst, S1 src1, S2 src2) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto sum = USub(lhs, rhs);
  WriteZExt(dst, sum);
  WriteFlagsAddSub<tag_sub>(state, lhs, rhs, sum);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(SUBPS, D dst, S1 src1, S2 src2) {
  FWriteV32(dst, FSubV32(FReadV32(src1), FReadV32(src2)));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(SUBPD, D dst, S1 src1, S2 src2) {
  FWriteV64(dst, FSubV64(FReadV64(src1), FReadV64(src2)));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(SUBSS, D dst, S1 src1, S2 src2) {
  auto lhs = FReadV32(src1);
  auto rhs = FReadV32(src2);
  auto sum = FSub(FExtractV32(lhs, 0), FExtractV32(rhs, 0));
  auto res = FInsertV32(lhs, 0, sum);
  FWriteV32(dst, res);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(SUBSD, D dst, S1 src1, S2 src2) {
  auto lhs = FReadV64(src1);
  auto rhs = FReadV64(src2);
  auto sum = FSub(FExtractV64(lhs, 0), FExtractV64(rhs, 0));
  auto res = FInsertV64(lhs, 0, sum);
  FWriteV64(dst, res);
  return memory;
}

}  // namespace

DEF_ISEL(SUB_MEMb_IMMb_80r5) = SUB<M8W, M8, I8>;
DEF_ISEL(SUB_GPR8_IMMb_80r5) = SUB<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(SUB_MEMv_IMMz, SUB);
DEF_ISEL_RnW_Rn_In(SUB_GPRv_IMMz, SUB);
DEF_ISEL(SUB_MEMb_IMMb_82r5) = SUB<M8W, M8, I8>;
DEF_ISEL(SUB_GPR8_IMMb_82r5) = SUB<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(SUB_MEMv_IMMb, SUB);
DEF_ISEL_RnW_Rn_In(SUB_GPRv_IMMb, SUB);
DEF_ISEL(SUB_MEMb_GPR8) = SUB<M8W, M8, I8>;
DEF_ISEL(SUB_GPR8_GPR8_28) = SUB<R8W, R8, R8>;
DEF_ISEL_MnW_Mn_Rn(SUB_MEMv_GPRv, SUB);
DEF_ISEL_RnW_Rn_Rn(SUB_GPRv_GPRv_29, SUB);
DEF_ISEL(SUB_GPR8_GPR8_2A) = SUB<R8W, R8, R8>;
DEF_ISEL(SUB_GPR8_MEMb) = SUB<R8W, R8, M8>;
DEF_ISEL_RnW_Rn_Rn(SUB_GPRv_GPRv_2B, SUB);
DEF_ISEL_RnW_Rn_Mn(SUB_GPRv_MEMv, SUB);
DEF_ISEL(SUB_AL_IMMb) = SUB<R8W, R8, I8>;
DEF_ISEL_RnW_Rn_In(SUB_OrAX_IMMz, SUB);

DEF_ISEL(SUBPS_XMMps_MEMps) = SUBPS<V128W, V128, MV128>;
DEF_ISEL(SUBPS_XMMps_XMMps) = SUBPS<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VSUBPS_XMMdq_XMMdq_MEMdq) = SUBPS<VV128W, VV128, MV128>;)
IF_AVX(DEF_ISEL(VSUBPS_XMMdq_XMMdq_XMMdq) = SUBPS<VV128W, VV128, VV128>;)
IF_AVX(DEF_ISEL(VSUBPS_YMMqq_YMMqq_MEMqq) = SUBPS<VV256W, VV256, MV256>;)
IF_AVX(DEF_ISEL(VSUBPS_YMMqq_YMMqq_YMMqq) = SUBPS<VV256W, VV256, VV256>;)

DEF_ISEL(SUBPD_XMMpd_MEMpd) = SUBPD<V128W, V128, MV128>;
DEF_ISEL(SUBPD_XMMpd_XMMpd) = SUBPD<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VSUBPD_XMMdq_XMMdq_MEMdq) = SUBPD<VV128W, VV128, MV128>;)
IF_AVX(DEF_ISEL(VSUBPD_XMMdq_XMMdq_XMMdq) = SUBPD<VV128W, VV128, VV128>;)
IF_AVX(DEF_ISEL(VSUBPD_YMMqq_YMMqq_MEMqq) = SUBPD<VV256W, VV256, MV256>;)
IF_AVX(DEF_ISEL(VSUBPD_YMMqq_YMMqq_YMMqq) = SUBPD<VV256W, VV256, VV256>;)

DEF_ISEL(SUBSS_XMMss_MEMss) = SUBSS<V128W, V128, MV32>;
DEF_ISEL(SUBSS_XMMss_XMMss) = SUBSS<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VSUBSS_XMMdq_XMMdq_MEMd) = SUBSS<VV128W, VV128, MV32>;)
IF_AVX(DEF_ISEL(VSUBSS_XMMdq_XMMdq_XMMd) = SUBSS<VV128W, VV128, VV128>;)

DEF_ISEL(SUBSD_XMMsd_MEMsd) = SUBSD<V128W, V128, MV64>;
DEF_ISEL(SUBSD_XMMsd_XMMsd) = SUBSD<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VSUBSD_XMMdq_XMMdq_MEMq) = SUBSD<VV128W, VV128, MV64>;)
IF_AVX(DEF_ISEL(VSUBSD_XMMdq_XMMdq_XMMq) = SUBSD<VV128W, VV128, VV128>;)

namespace {

template <typename S1, typename S2>
DEF_SEM(CMP, S1 src1, S2 src2) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto sum = USub(lhs, rhs);
  WriteFlagsAddSub<tag_sub>(state, lhs, rhs, sum);
  return memory;
}

}  // namespace

DEF_ISEL(CMP_MEMb_IMMb_80r7) = CMP<M8, I8>;
DEF_ISEL(CMP_GPR8_IMMb_80r7) = CMP<R8, I8>;
DEF_ISEL_Mn_In(CMP_MEMv_IMMz, CMP);
DEF_ISEL_Rn_In(CMP_GPRv_IMMz, CMP);
DEF_ISEL(CMP_MEMb_IMMb_82r7) = CMP<M8, I8>;
DEF_ISEL(CMP_GPR8_IMMb_82r7) = CMP<R8, I8>;
DEF_ISEL_Mn_In(CMP_MEMv_IMMb, CMP);
DEF_ISEL_Rn_In(CMP_GPRv_IMMb, CMP);
DEF_ISEL(CMP_MEMb_GPR8) = CMP<M8, I8>;
DEF_ISEL(CMP_GPR8_GPR8_38) = CMP<R8, R8>;
DEF_ISEL_Mn_In(CMP_MEMv_GPRv, CMP);
DEF_ISEL_Rn_Rn(CMP_GPRv_GPRv_39, CMP);
DEF_ISEL(CMP_GPR8_GPR8_3A) = CMP<R8, R8>;
DEF_ISEL(CMP_GPR8_MEMb) = CMP<R8, M8>;
DEF_ISEL_Rn_Rn(CMP_GPRv_GPRv_3B, CMP);
DEF_ISEL_Rn_Mn(CMP_GPRv_MEMv, CMP);
DEF_ISEL(CMP_AL_IMMb) = CMP<R8, I8>;
DEF_ISEL_Rn_In(CMP_OrAX_IMMz, CMP);

namespace {

template <typename T, typename U, typename V>
ALWAYS_INLINE static void WriteFlagsMul(State &state, T lhs, T rhs, U res,
                                        V res_trunc) {
  const auto new_of = Overflow<tag_mul>::Flag(lhs, rhs, res);
  FLAG_CF = new_of;
  FLAG_PF = BUndefined();  // Technically undefined.
  FLAG_AF = BUndefined();
  FLAG_ZF = BUndefined();
  FLAG_SF = BUndefined();
  FLAG_OF = new_of;
}

// 2-operand and 3-operand multipliers truncate their results down to their
// base types.
template <typename D, typename S1, typename S2>
DEF_SEM(IMUL, D dst, S1 src1, S2 src2) {
  auto lhs = Signed(Read(src1));
  auto rhs = Signed(Read(src2));
  auto lhs_wide = SExt(lhs);
  auto rhs_wide = SExt(rhs);
  auto res = SMul(lhs_wide, rhs_wide);
  auto res_trunc = TruncTo<S2>(res);
  WriteZExt(dst, res_trunc);  // E.g. write to EAX can overwrite RAX.
  WriteFlagsMul(state, lhs, rhs, res, res_trunc);
  return memory;
}

// Unsigned multiply without affecting flags.
template <typename D, typename S2>
DEF_SEM(MULX, D dst1, D dst2, const S2 src2) {
  auto lhs = ZExt(Read(src2));

  // Kind of tricky: in 64-bit, for a 32-bit MULX, we read RDX, but we need
  // to truncate it down into EDX before extending it back up to "double" its
  // width.
  auto rhs = ZExt(TruncTo<S2>(Read(REG_XDX)));
  auto res = UMul(lhs, rhs);
  auto res_high = UShr(res, ZExt(BitSizeOf(src2)));

  // In 64-bit, a 32-bit dest needs to zero-extend up to 64 bits because the
  // write version of the reg will be the 64-bit version.
  WriteZExt(dst1, TruncTo<S2>(res_high));  // High N bits.
  WriteZExt(dst2, TruncTo<S2>(res));  // Low N bits.
  return memory;
}

#define MAKE_MULxax(name, src1, dst1, dst2) \
  template <typename S2> \
  DEF_SEM(MUL##name, S2 src2) { \
    auto lhs = Read(src1); \
    auto rhs = Read(src2); \
    auto lhs_wide = ZExt(lhs); \
    auto rhs_wide = ZExt(rhs); \
    auto res = UMul(lhs_wide, rhs_wide); \
    auto res_trunc = Trunc(res); \
    auto shift = ZExt(BitSizeOf(src2)); \
    WriteZExt(dst1, res_trunc); \
    WriteZExt(dst2, Trunc(UShr(res, shift))); \
    WriteFlagsMul(state, lhs, rhs, res, res_trunc); \
    return memory; \
  }

MAKE_MULxax(al, REG_AL, REG_AL, REG_AH) MAKE_MULxax(ax, REG_AX, REG_AX, REG_DX)
    MAKE_MULxax(eax, REG_EAX, REG_XAX, REG_XDX)
        IF_64BIT(MAKE_MULxax(rax, REG_RAX, REG_RAX, REG_RDX))

#undef MAKE_MULxax

#define MAKE_IMULxax(name, src1, dst1, dst2) \
  template <typename S2> \
  DEF_SEM(IMUL##name, S2 src2) { \
    auto lhs = Signed(Read(src1)); \
    auto rhs = Signed(Read(src2)); \
    auto lhs_wide = SExt(lhs); \
    auto rhs_wide = SExt(rhs); \
    auto res = SMul(lhs_wide, rhs_wide); \
    auto res_trunc = Trunc(res); \
    auto shift = ZExt(BitSizeOf(src2)); \
    WriteZExt(dst1, Unsigned(res_trunc)); \
    WriteZExt(dst2, Trunc(UShr(Unsigned(res), shift))); \
    WriteFlagsMul(state, lhs, rhs, res, res_trunc); \
    return memory; \
  }

            MAKE_IMULxax(al, REG_AL, REG_AL, REG_AH)
                MAKE_IMULxax(ax, REG_AX, REG_AX, REG_DX)
                    MAKE_IMULxax(eax, REG_EAX, REG_XAX, REG_XDX)
                        IF_64BIT(MAKE_IMULxax(rax, REG_RAX, REG_RAX, REG_RDX))

#undef MAKE_IMULxax

                            template <typename D, typename S1, typename S2>
                            DEF_SEM(MULPS, D dst, S1 src1, S2 src2) {
  FWriteV32(dst, FMulV32(FReadV32(src1), FReadV32(src2)));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(MULPD, D dst, S1 src1, S2 src2) {
  FWriteV64(dst, FMulV64(FReadV64(src1), FReadV64(src2)));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(MULSS, D dst, S1 src1, S2 src2) {
  auto lhs = FReadV32(src1);
  auto rhs = FReadV32(src2);
  auto mul = FMul(FExtractV32(lhs, 0), FExtractV32(rhs, 0));
  auto res = FInsertV32(lhs, 0, mul);
  FWriteV32(dst, res);  // SSE: Writes to XMM, AVX: Zero-extends XMM.
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(MULSD, D dst, S1 src1, S2 src2) {
  auto lhs = FReadV64(src1);
  auto rhs = FReadV64(src2);
  auto mul = FMul(FExtractV64(lhs, 0), FExtractV64(rhs, 0));
  auto res = FInsertV64(lhs, 0, mul);
  FWriteV64(dst, res);  // SSE: Writes to XMM, AVX: Zero-extends XMM.
  return memory;
}

}  // namespace

DEF_ISEL(IMUL_MEMb) = IMULal<M8>;
DEF_ISEL(IMUL_GPR8) = IMULal<R8>;
DEF_ISEL(IMUL_MEMv_8) = IMULal<M8>;
DEF_ISEL(IMUL_MEMv_16) = IMULax<M16>;
DEF_ISEL(IMUL_MEMv_32) = IMULeax<M32>;
IF_64BIT(DEF_ISEL(IMUL_MEMv_64) = IMULrax<M64>;)
DEF_ISEL(IMUL_GPRv_8) = IMULal<R8>;
DEF_ISEL(IMUL_GPRv_16) = IMULax<R16>;
DEF_ISEL(IMUL_GPRv_32) = IMULeax<R32>;
IF_64BIT(DEF_ISEL(IMUL_GPRv_64) = IMULrax<R64>;)

// All dests are registers, albeit different ones from the sources.
DEF_ISEL_RnW_Mn_In(IMUL_GPRv_MEMv_IMMz, IMUL);
DEF_ISEL_RnW_Rn_In(IMUL_GPRv_GPRv_IMMz, IMUL);
DEF_ISEL_RnW_Mn_In(IMUL_GPRv_MEMv_IMMb, IMUL);
DEF_ISEL_RnW_Rn_In(IMUL_GPRv_GPRv_IMMb, IMUL);

// Two-operand, but dest is a register so turns into a three-operand.
DEF_ISEL_RnW_Rn_Mn(IMUL_GPRv_MEMv, IMUL);
DEF_ISEL_RnW_Rn_Rn(IMUL_GPRv_GPRv, IMUL);

DEF_ISEL(MUL_GPR8) = MULal<R8>;
DEF_ISEL(MUL_MEMb) = MULal<M8>;
DEF_ISEL(MUL_MEMv_8) = MULal<M8>;
DEF_ISEL(MUL_MEMv_16) = MULax<M16>;
DEF_ISEL(MUL_MEMv_32) = MULeax<M32>;
IF_64BIT(DEF_ISEL(MUL_MEMv_64) = MULrax<M64>;)
DEF_ISEL(MUL_GPRv_8) = MULal<R8>;
DEF_ISEL(MUL_GPRv_16) = MULax<R16>;
DEF_ISEL(MUL_GPRv_32) = MULeax<R32>;
IF_64BIT(DEF_ISEL(MUL_GPRv_64) = MULrax<R64>;)

DEF_ISEL(MULX_VGPR32d_VGPR32d_VGPR32d) = MULX<R32W, R32>;
DEF_ISEL(MULX_VGPR32d_VGPR32d_MEMd) = MULX<R32W, M32>;
IF_64BIT(DEF_ISEL(MULX_VGPR64q_VGPR64q_VGPR64q) = MULX<R64W, R64>;)
IF_64BIT(DEF_ISEL(MULX_VGPR64q_VGPR64q_MEMq) = MULX<R64W, M64>;)

DEF_ISEL(MULPS_XMMps_MEMps) = MULPS<V128W, V128, MV128>;
DEF_ISEL(MULPS_XMMps_XMMps) = MULPS<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VMULPS_XMMdq_XMMdq_MEMdq) = MULPS<VV128W, VV128, MV128>;)
IF_AVX(DEF_ISEL(VMULPS_XMMdq_XMMdq_XMMdq) = MULPS<VV128W, VV128, VV128>;)
IF_AVX(DEF_ISEL(VMULPS_YMMqq_YMMqq_MEMqq) = MULPS<VV256W, VV256, MV256>;)
IF_AVX(DEF_ISEL(VMULPS_YMMqq_YMMqq_YMMqq) = MULPS<VV256W, VV256, VV256>;)

DEF_ISEL(MULPD_XMMpd_MEMpd) = MULPD<V128W, V128, MV128>;
DEF_ISEL(MULPD_XMMpd_XMMpd) = MULPD<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VMULPD_XMMdq_XMMdq_MEMdq) = MULPD<VV128W, VV128, MV128>;)
IF_AVX(DEF_ISEL(VMULPD_XMMdq_XMMdq_XMMdq) = MULPD<VV128W, VV128, VV128>;)
IF_AVX(DEF_ISEL(VMULPD_YMMqq_YMMqq_MEMqq) = MULPD<VV256W, VV256, MV256>;)
IF_AVX(DEF_ISEL(VMULPD_YMMqq_YMMqq_YMMqq) = MULPD<VV256W, VV256, VV256>;)

DEF_ISEL(MULSS_XMMss_MEMss) = MULSS<V128W, V128, MV128>;
DEF_ISEL(MULSS_XMMss_XMMss) = MULSS<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VMULSS_XMMdq_XMMdq_MEMd) = MULSS<VV128W, VV128, MV128>;)
IF_AVX(DEF_ISEL(VMULSS_XMMdq_XMMdq_XMMd) = MULSS<VV128W, VV128, VV128>;)

DEF_ISEL(MULSD_XMMsd_MEMsd) = MULSD<V128W, V128, MV128>;
DEF_ISEL(MULSD_XMMsd_XMMsd) = MULSD<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VMULSD_XMMdq_XMMdq_MEMq) = MULSD<VV128W, VV128, MV128>;)
IF_AVX(DEF_ISEL(VMULSD_XMMdq_XMMdq_XMMq) = MULSD<VV128W, VV128, VV128>;)

namespace {

// TODO(pag): Is the checking of `res` against `res_trunc` worth it? It
//            introduces extra control flow.
#define MAKE_DIVxax(name, src1, src2, dst1, dst2) \
  template <typename S3> \
  DEF_SEM(DIV##name, S3 src3, PC next_pc) { \
    auto lhs_low = ZExt(Read(src1)); \
    auto lhs_high = ZExt(Read(src2)); \
    auto rhs = ZExt(Read(src3)); \
    auto shift = ZExt(BitSizeOf(src3)); \
    auto lhs = UOr(UShl(lhs_high, shift), lhs_low); \
    WriteZExt(REG_PC, Read(next_pc)); \
    if (IsZero(rhs)) { \
      StopFailure(); \
    } else { \
      auto quot = UDiv(lhs, rhs); \
      auto rem = URem(lhs, rhs); \
      auto quot_trunc = Trunc(quot); \
      auto rem_trunc = Trunc(rem); \
      if (quot != ZExt(quot_trunc)) { \
        StopFailure(); \
      } else { \
        WriteZExt(dst1, quot_trunc); \
        WriteZExt(dst2, rem_trunc); \
        ClearArithFlags(); \
        return memory; \
      } \
    } \
  }

MAKE_DIVxax(ax, REG_AL, REG_AH, REG_AL, REG_AH)
    MAKE_DIVxax(dxax, REG_AX, REG_DX, REG_AX, REG_DX)
        MAKE_DIVxax(edxeax, REG_EAX, REG_EDX, REG_XAX, REG_XDX)
            IF_64BIT(MAKE_DIVxax(rdxrax, REG_RAX, REG_RDX, REG_RAX, REG_RDX))

#undef MAKE_DIVxax

// TODO(pag): Is the checking of `res` against `res_trunc` worth it? It
//            introduces extra control flow.
#define MAKE_IDIVxax(name, src1, src2, dst1, dst2) \
  template <typename S3> \
  DEF_SEM(IDIV##name, S3 src3, PC next_pc) { \
    auto lhs_low = ZExt(Read(src1)); \
    auto lhs_high = ZExt(Read(src2)); \
    auto rhs = SExt(Read(src3)); \
    auto shift = ZExt(BitSizeOf(src3)); \
    auto lhs = Signed(UOr(UShl(lhs_high, shift), lhs_low)); \
    WriteZExt(REG_PC, Read(next_pc)); \
    if (IsZero(rhs)) { \
      StopFailure(); \
    } else { \
      auto quot = SDiv(lhs, rhs); \
      auto rem = SRem(lhs, rhs); \
      auto quot_trunc = Trunc(quot); \
      auto rem_trunc = Trunc(rem); \
      if (quot != SExt(quot_trunc)) { \
        StopFailure(); \
      } else { \
        WriteZExt(dst1, Unsigned(quot_trunc)); \
        WriteZExt(dst2, Unsigned(rem_trunc)); \
        ClearArithFlags(); \
        return memory; \
      } \
    } \
  }

                MAKE_IDIVxax(ax, REG_AL, REG_AH, REG_AL, REG_AH)
                    MAKE_IDIVxax(dxax, REG_AX, REG_DX, REG_AX, REG_DX)
                        MAKE_IDIVxax(edxeax, REG_EAX, REG_EDX, REG_XAX, REG_XDX)
                            IF_64BIT(MAKE_IDIVxax(rdxrax, REG_RAX, REG_RDX,
                                                  REG_RAX, REG_RDX))

#undef MAKE_IDIVxax

}  // namespace

DEF_ISEL(IDIV_MEMb) = IDIVax<M8>;
DEF_ISEL(IDIV_GPR8) = IDIVax<R8>;
DEF_ISEL(IDIV_MEMv_8) = IDIVax<M8>;
DEF_ISEL(IDIV_MEMv_16) = IDIVdxax<M16>;
DEF_ISEL(IDIV_MEMv_32) = IDIVedxeax<M32>;
IF_64BIT(DEF_ISEL(IDIV_MEMv_64) = IDIVrdxrax<M64>;)
DEF_ISEL(IDIV_GPRv_8) = IDIVax<R8>;
DEF_ISEL(IDIV_GPRv_16) = IDIVdxax<R16>;
DEF_ISEL(IDIV_GPRv_32) = IDIVedxeax<R32>;
IF_64BIT(DEF_ISEL(IDIV_GPRv_64) = IDIVrdxrax<R64>;)

DEF_ISEL(DIV_MEMb) = DIVax<M8>;
DEF_ISEL(DIV_GPR8) = DIVax<R8>;
DEF_ISEL(DIV_MEMv_8) = DIVax<M8>;
DEF_ISEL(DIV_MEMv_16) = DIVdxax<M16>;
DEF_ISEL(DIV_MEMv_32) = DIVedxeax<M32>;
IF_64BIT(DEF_ISEL(DIV_MEMv_64) = DIVrdxrax<M64>;)
DEF_ISEL(DIV_GPRv_8) = DIVax<R8>;
DEF_ISEL(DIV_GPRv_16) = DIVdxax<R16>;
DEF_ISEL(DIV_GPRv_32) = DIVedxeax<R32>;
IF_64BIT(DEF_ISEL(DIV_GPRv_64) = DIVrdxrax<R64>;)

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(DIVPS, D dst, S1 src1, S2 src2) {
  FWriteV32(dst, FDivV32(FReadV32(src1), FReadV32(src2)));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(DIVPD, D dst, const S1 src1, const S2 src2) {
  FWriteV64(dst, FDivV64(FReadV64(src1), FReadV64(src2)));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(DIVSS, D dst, S1 src1, S2 src2) {
  auto lhs = FReadV32(src1);
  auto rhs = FReadV32(src2);
  auto quot = FDiv(FExtractV32(lhs, 0), FExtractV32(rhs, 0));
  auto res = FInsertV32(lhs, 0, quot);
  FWriteV32(dst, res);  // SSE: Writes to XMM, AVX: Zero-extends XMM.
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(DIVSD, D dst, S1 src1, S2 src2) {
  auto lhs = FReadV64(src1);
  auto rhs = FReadV64(src2);
  auto quot = FDiv(FExtractV64(lhs, 0), FExtractV64(rhs, 0));
  auto res = FInsertV64(lhs, 0, quot);
  FWriteV64(dst, res);  // SSE: Writes to XMM, AVX: Zero-extends XMM.
  return memory;
}

}  // namespace

DEF_ISEL(DIVPS_XMMps_MEMps) = DIVPS<V128W, V128, MV128>;
DEF_ISEL(DIVPS_XMMps_XMMps) = DIVPS<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VDIVPS_XMMdq_XMMdq_MEMdq) = DIVPS<VV128W, VV128, MV128>;)
IF_AVX(DEF_ISEL(VDIVPS_XMMdq_XMMdq_XMMdq) = DIVPS<VV128W, VV128, VV128>;)
IF_AVX(DEF_ISEL(VDIVPS_YMMqq_YMMqq_MEMqq) = DIVPS<VV256W, VV256, MV256>;)
IF_AVX(DEF_ISEL(VDIVPS_YMMqq_YMMqq_YMMqq) = DIVPS<VV256W, VV256, VV256>;)

DEF_ISEL(DIVPD_XMMpd_MEMpd) = DIVPD<V128W, V128, MV128>;
DEF_ISEL(DIVPD_XMMpd_XMMpd) = DIVPD<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VDIVPD_XMMdq_XMMdq_MEMdq) = DIVPD<VV128W, VV128, MV128>;)
IF_AVX(DEF_ISEL(VDIVPD_XMMdq_XMMdq_XMMdq) = DIVPD<VV128W, VV128, VV128>;)
IF_AVX(DEF_ISEL(VDIVPD_YMMqq_YMMqq_MEMqq) = DIVPD<VV256W, VV256, MV256>;)
IF_AVX(DEF_ISEL(VDIVPD_YMMqq_YMMqq_YMMqq) = DIVPD<VV256W, VV256, VV256>;)

DEF_ISEL(DIVSS_XMMss_MEMss) = DIVSS<V128W, V128, MV128>;
DEF_ISEL(DIVSS_XMMss_XMMss) = DIVSS<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VDIVSS_XMMdq_XMMdq_MEMd) = DIVSS<VV128W, VV128, MV128>;)
IF_AVX(DEF_ISEL(VDIVSS_XMMdq_XMMdq_XMMd) = DIVSS<VV128W, VV128, VV128>;)

DEF_ISEL(DIVSD_XMMsd_MEMsd) = DIVSD<V128W, V128, MV128>;
DEF_ISEL(DIVSD_XMMsd_XMMsd) = DIVSD<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VDIVSD_XMMdq_XMMdq_MEMq) = DIVSD<VV128W, VV128, MV128>;)
IF_AVX(DEF_ISEL(VDIVSD_XMMdq_XMMdq_XMMq) = DIVSD<VV128W, VV128, VV128>;)

namespace {

template <typename D, typename S1>
DEF_SEM(INC, D dst, S1 src) {
  auto lhs = Read(src);
  decltype(lhs) rhs = 1;
  auto sum = UAdd(lhs, rhs);
  WriteZExt(dst, sum);
  WriteFlagsIncDec<tag_add>(state, lhs, rhs, sum);
  return memory;
}

template <typename D, typename S1>
DEF_SEM(DEC, D dst, S1 src) {
  auto lhs = Read(src);
  auto_t(S1) rhs = 1;
  auto sum = USub(lhs, rhs);
  WriteZExt(dst, sum);
  WriteFlagsIncDec<tag_sub>(state, lhs, rhs, sum);
  return memory;
}

template <typename D, typename S1>
DEF_SEM(NEG, D dst, S1 src) {
  auto_t(S1) lhs = 0;
  auto rhs = Read(src);
  auto neg = UNeg(rhs);
  WriteZExt(dst, neg);
  WriteFlagsAddSub<tag_sub>(state, lhs, rhs, neg);
  return memory;
}

}  // namespace

DEF_ISEL(INC_MEMb) = INC<M8W, M8>;
DEF_ISEL(INC_GPR8) = INC<R8W, R8>;
DEF_ISEL_MnW_Mn(INC_MEMv, INC);
DEF_ISEL_RnW_Rn(INC_GPRv_FFr0, INC);
DEF_ISEL_RnW_Rn(INC_GPRv_40, INC);

DEF_ISEL(DEC_MEMb) = DEC<M8W, M8>;
DEF_ISEL(DEC_GPR8) = DEC<R8W, R8>;
DEF_ISEL_MnW_Mn(DEC_MEMv, DEC);
DEF_ISEL_RnW_Rn(DEC_GPRv_FFr1, DEC);
DEF_ISEL_RnW_Rn(DEC_GPRv_48, DEC);

DEF_ISEL(NEG_MEMb) = NEG<M8W, M8>;
DEF_ISEL(NEG_GPR8) = NEG<R8W, R8>;
DEF_ISEL_MnW_Mn(NEG_MEMv, NEG);
DEF_ISEL_RnW_Rn(NEG_GPRv, NEG);

namespace {

template <typename TagT, typename T>
ALWAYS_INLINE static bool CarryFlag(T a, T b, T ab, T c, T abc) {
  static_assert(std::is_unsigned<T>::value,
                "Invalid specialization of `CarryFlag` for addition.");
  return Carry<TagT>::Flag(a, b, ab) || Carry<TagT>::Flag(ab, c, abc);
}

template <typename D, typename S1, typename S2>
DEF_SEM(ADC, D dst, S1 src1, S2 src2) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto carry = ZExtTo<S1>(Unsigned(Read(FLAG_CF)));
  auto sum = UAdd(lhs, rhs);
  auto res = UAdd(sum, carry);
  WriteZExt(dst, res);
  Write(FLAG_CF, CarryFlag<tag_add>(lhs, rhs, sum, carry, res));
  WriteFlagsIncDec<tag_add>(state, lhs, rhs, res);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(SBB, D dst, S1 src1, S2 src2) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto borrow = ZExtTo<S1>(Unsigned(Read(FLAG_CF)));
  auto sum = USub(lhs, rhs);
  auto res = USub(sum, borrow);
  WriteZExt(dst, res);
  Write(FLAG_CF, CarryFlag<tag_sub>(lhs, rhs, sum, borrow, res));
  WriteFlagsIncDec<tag_sub>(state, lhs, rhs, res);
  return memory;
}

}  // namespace

DEF_ISEL(SBB_MEMb_IMMb_80r3) = SBB<M8W, M8, I8>;
DEF_ISEL(SBB_GPR8_IMMb_80r3) = SBB<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(SBB_MEMv_IMMz, SBB);
DEF_ISEL_RnW_Rn_In(SBB_GPRv_IMMz, SBB);
DEF_ISEL(SBB_MEMb_IMMb_82r3) = SBB<M8W, M8, I8>;
DEF_ISEL(SBB_GPR8_IMMb_82r3) = SBB<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(SBB_MEMv_IMMb, SBB);
DEF_ISEL_RnW_Rn_In(SBB_GPRv_IMMb, SBB);
DEF_ISEL(SBB_MEMb_GPR8) = SBB<M8W, M8, I8>;
DEF_ISEL(SBB_GPR8_GPR8_18) = SBB<R8W, R8, R8>;
DEF_ISEL_MnW_Mn_Rn(SBB_MEMv_GPRv, SBB);
DEF_ISEL_RnW_Rn_Rn(SBB_GPRv_GPRv_19, SBB);
DEF_ISEL(SBB_GPR8_GPR8_1A) = SBB<R8W, R8, R8>;
DEF_ISEL(SBB_GPR8_MEMb) = SBB<R8W, R8, M8>;
DEF_ISEL_RnW_Rn_Rn(SBB_GPRv_GPRv_1B, SBB);
DEF_ISEL_RnW_Rn_Mn(SBB_GPRv_MEMv, SBB);
DEF_ISEL(SBB_AL_IMMb) = SBB<R8W, R8, I8>;
DEF_ISEL_RnW_Rn_In(SBB_OrAX_IMMz, SBB);

DEF_ISEL(ADC_MEMb_IMMb_80r2) = ADC<M8W, M8, I8>;
DEF_ISEL(ADC_GPR8_IMMb_80r2) = ADC<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(ADC_MEMv_IMMz, ADC);
DEF_ISEL_RnW_Rn_In(ADC_GPRv_IMMz, ADC);
DEF_ISEL(ADC_MEMb_IMMb_82r2) = ADC<M8W, M8, I8>;
DEF_ISEL(ADC_GPR8_IMMb_82r2) = ADC<R8W, R8, I8>;
DEF_ISEL_MnW_Mn_In(ADC_MEMv_IMMb, ADC);
DEF_ISEL_RnW_Rn_In(ADC_GPRv_IMMb, ADC);
DEF_ISEL(ADC_MEMb_GPR8) = ADC<M8W, M8, R8>;
DEF_ISEL(ADC_GPR8_GPR8_10) = ADC<R8W, R8, R8>;
DEF_ISEL_MnW_Mn_Rn(ADC_MEMv_GPRv, ADC);
DEF_ISEL_RnW_Rn_Rn(ADC_GPRv_GPRv_11, ADC);
DEF_ISEL(ADC_GPR8_MEMb) = ADC<R8W, R8, M8>;
DEF_ISEL(ADC_GPR8_GPR8_12) = ADC<R8W, R8, R8>;
DEF_ISEL_RnW_Rn_Mn(ADC_GPRv_MEMv, ADC);
DEF_ISEL_RnW_Rn_Rn(ADC_GPRv_GPRv_13, ADC);
DEF_ISEL(ADC_AL_IMMb) = ADC<R8W, R8, I8>;
DEF_ISEL_RnW_Rn_In(ADC_OrAX_IMMz, ADC);
