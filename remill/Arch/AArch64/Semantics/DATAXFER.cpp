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

DEF_SEM(StorePairUpdateIndex32, R32 src1, R32 src2, MV64W dst_mem,
                                R64W dst_reg, ADDR next_addr) {
  uint32v2_t vec = {};
  vec = UInsertV32(vec, 0, Read(src1));
  vec = UInsertV32(vec, 1, Read(src2));
  UWriteV32(dst_mem, vec);
  Write(dst_reg, Read(next_addr));
  return memory;
}

DEF_SEM(StorePairUpdateIndex64, R64 src1, R64 src2, MV128W dst_mem,
                                R64W dst_reg, ADDR next_addr) {
  uint64v2_t vec = {};
  vec = UInsertV64(vec, 0, Read(src1));
  vec = UInsertV64(vec, 1, Read(src2));
  UWriteV64(dst_mem, vec);
  Write(dst_reg, Read(next_addr));
  return memory;
}

DEF_SEM(StorePair32, R32 src1, R32 src2, MV64W dst) {
  uint32v2_t vec = {};
  UWriteV32(dst, UInsertV32(UInsertV32(vec, 0, Read(src1)), 1, Read(src2)));
  return memory;
}

DEF_SEM(StorePair64, R64 src1, R64 src2, MV128W dst) {
  uint64v2_t vec = {};
  UWriteV64(dst, UInsertV64(UInsertV64(vec, 0, Read(src1)), 1, Read(src2)));
  return memory;
}

DEF_SEM(STP_S, V32 src1, V32 src2, MV64W dst) {
  auto src1_vec = FReadV32(src1);
  auto src2_vec = FReadV32(src2);
  float32v2_t tmp_vec = {};
  tmp_vec = FInsertV32(tmp_vec, 0, FExtractV32(src1_vec, 0));
  tmp_vec = FInsertV32(tmp_vec, 1, FExtractV32(src2_vec, 0));
  FWriteV32(dst, tmp_vec);
  return memory;
}

DEF_SEM(STP_D, V64 src1, V64 src2, MV128W dst) {
  auto src1_vec = FReadV64(src1);
  auto src2_vec = FReadV64(src2);
  float64v2_t tmp_vec = {};
  tmp_vec = FInsertV64(tmp_vec, 0, FExtractV64(src1_vec, 0));
  tmp_vec = FInsertV64(tmp_vec, 1, FExtractV64(src2_vec, 0));
  FWriteV64(dst, tmp_vec);
  return memory;
}

// MvW type isnt supported
// remill/remill/Arch/Runtime/Operators.h:437:1: error: static_assert failed "Invalid value size for MVnW."
// MAKE_MWRITEV(U, 128, dqwords, 128, uint128_t)

// DEF_SEM(STP_Q, V128 src1, V128 src2, MV128W dst) {
//   auto src1_vec = UReadV128(src1);
//   auto src2_vec = UReadV128(src2);
//   uint128v2_t tmp_vec = {};
//   tmp_vec = UInsertV128(tmp_vec, 0, UExtractV128(src1_vec, 0));
//   tmp_vec = UInsertV128(tmp_vec, 1, UExtractV128(src2_vec, 0));
//   UWriteV128(dst, tmp_vec);
//   return memory;
// }
}  // namespace

DEF_ISEL(STP_32_LDSTPAIR_PRE) = StorePairUpdateIndex32;
DEF_ISEL(STP_32_LDSTPAIR_POST) = StorePairUpdateIndex32;

DEF_ISEL(STP_64_LDSTPAIR_PRE) = StorePairUpdateIndex64;
DEF_ISEL(STP_64_LDSTPAIR_POST) = StorePairUpdateIndex64;

DEF_ISEL(STP_32_LDSTPAIR_OFF) = StorePair32;
DEF_ISEL(STP_64_LDSTPAIR_OFF) = StorePair64;

DEF_ISEL(STP_S_LDSTPAIR_OFF) = STP_S;
DEF_ISEL(STP_D_LDSTPAIR_OFF) = STP_D;
// DEF_ISEL(STP_Q_LDSTPAIR_OFF) = STP_Q;

namespace {

template <typename S, typename D>
DEF_SEM(StoreUpdateIndex, S src, D dst_mem, R64W dst_reg, ADDR next_addr) {
  WriteTrunc(dst_mem, Read(src));
  Write(dst_reg, Read(next_addr));
  return memory;
}

template <typename S, typename D>
DEF_SEM(Store, S src, D dst) {
  WriteTrunc(dst, Read(src));
  return memory;
}

template <typename S, typename D>
DEF_SEM(StoreToOffset, S src, D base, ADDR offset) {
  WriteTrunc(DisplaceAddress(base, Read(offset)), Read(src));
  return memory;
}

}  // namespace

DEF_ISEL(STR_32_LDST_IMMPRE) = StoreUpdateIndex<R32, M32W>;
DEF_ISEL(STR_32_LDST_IMMPOST) = StoreUpdateIndex<R32, M32W>;

DEF_ISEL(STR_64_LDST_IMMPRE) = StoreUpdateIndex<R64, M64W>;
DEF_ISEL(STR_64_LDST_IMMPOST) = StoreUpdateIndex<R64, M64W>;

DEF_ISEL(STR_32_LDST_POS) = Store<R32, M32W>;
DEF_ISEL(STR_64_LDST_POS) = Store<R64, M64W>;

DEF_ISEL(STRB_32_LDST_POS) = Store<R32, M8W>;
DEF_ISEL(STRB_32_LDST_IMMPOST) = StoreUpdateIndex<R32, M8W>;
DEF_ISEL(STRB_32_LDST_IMMPRE) = StoreUpdateIndex<R32, M8W>;
DEF_ISEL(STRB_32B_LDST_REGOFF) = StoreToOffset<R32, M8W>;
DEF_ISEL(STRB_32BL_LDST_REGOFF) = StoreToOffset<R32, M8W>;

DEF_ISEL(STRH_32_LDST_REGOFF) = StoreToOffset<R32, M16W>;
DEF_ISEL(STRH_32_LDST_IMMPRE) = StoreUpdateIndex<R32, M16W>;
DEF_ISEL(STRH_32_LDST_IMMPOST) = StoreUpdateIndex<R32, M16W>;
DEF_ISEL(STRH_32_LDST_POS) = Store<R32, M16W>;

DEF_ISEL(STR_32_LDST_REGOFF) = StoreToOffset<R32, M32W>;
DEF_ISEL(STR_64_LDST_REGOFF) = StoreToOffset<R64, M64W>;

namespace {

DEF_SEM(LoadPairUpdateIndex32, R32W dst1, R32W dst2, MV64 src_mem,
                               R64W dst_reg, ADDR next_addr) {
  auto vec = UReadV32(src_mem);
  WriteZExt(dst1, UExtractV32(vec, 0));
  WriteZExt(dst2, UExtractV32(vec, 1));
  Write(dst_reg, Read(next_addr));
  return memory;
}

DEF_SEM(LoadPairUpdateIndex64, R64W dst1, R64W dst2, MV128 src_mem,
                               R64W dst_reg, ADDR next_addr) {
  auto vec = UReadV64(src_mem);
  Write(dst1, UExtractV64(vec, 0));
  Write(dst2, UExtractV64(vec, 1));
  Write(dst_reg, Read(next_addr));
  return memory;
}

}  // namespace

DEF_ISEL(LDP_32_LDSTPAIR_PRE) = LoadPairUpdateIndex32;
DEF_ISEL(LDP_32_LDSTPAIR_POST) = LoadPairUpdateIndex32;

DEF_ISEL(LDP_64_LDSTPAIR_PRE) = LoadPairUpdateIndex64;
DEF_ISEL(LDP_64_LDSTPAIR_POST) = LoadPairUpdateIndex64;

namespace {

DEF_SEM(LoadPair32, R32W dst1, R32W dst2, MV64 src_mem) {
  auto vec = UReadV32(src_mem);
  WriteZExt(dst1, UExtractV32(vec, 0));
  WriteZExt(dst2, UExtractV32(vec, 1));
  return memory;
}

DEF_SEM(LoadPair64, R64W dst1, R64W dst2, MV128 src_mem) {
  auto vec = UReadV64(src_mem);
  Write(dst1, UExtractV64(vec, 0));
  Write(dst2, UExtractV64(vec, 1));
  return memory;
}

}  // namespace

DEF_ISEL(LDP_32_LDSTPAIR_OFF) = LoadPair32;
DEF_ISEL(LDP_64_LDSTPAIR_OFF) = LoadPair64;

namespace {

template <typename D, typename S>
DEF_SEM(Load, D dst, S src) {
  WriteZExt(dst, Read(src));
  return memory;
}

template <typename D, typename S>
DEF_SEM(LoadUpdateIndex, D dst, S src, R64W dst_reg, ADDR next_addr) {
  WriteZExt(dst, Read(src));
  Write(dst_reg, Read(next_addr));
  return memory;
}

template <typename D, typename M>
DEF_SEM(LoadFromOffset, D dst, M base, ADDR offset) {
  WriteZExt(dst, Read(DisplaceAddress(base, Read(offset))));
  return memory;
}
}  // namespace

DEF_ISEL(LDRB_32_LDST_POS) = Load<R32W, M8>;
DEF_ISEL(LDRB_32_LDST_IMMPOST) = LoadUpdateIndex<R32W, M8>;
DEF_ISEL(LDRB_32_LDST_IMMPRE) = LoadUpdateIndex<R32W, M8>;
DEF_ISEL(LDRB_32B_LDST_REGOFF) = LoadFromOffset<R32W, M8>;
DEF_ISEL(LDRB_32BL_LDST_REGOFF) = LoadFromOffset<R32W, M8>;

DEF_ISEL(LDRH_32_LDST_POS) = Load<R32W, M16>;
DEF_ISEL(LDRH_32_LDST_IMMPOST) = LoadUpdateIndex<R32W, M16>;
DEF_ISEL(LDRH_32_LDST_IMMPRE) = LoadUpdateIndex<R32W, M16>;
DEF_ISEL(LDRH_32_LDST_REGOFF) = LoadFromOffset<R32W, M16>;

DEF_ISEL(LDR_32_LDST_POS) = Load<R32W, M32>;
DEF_ISEL(LDR_32_LDST_IMMPOST) = LoadUpdateIndex<R32W, M32>;
DEF_ISEL(LDR_32_LDST_IMMPRE) = LoadUpdateIndex<R32W, M32>;
DEF_ISEL(LDR_32_LDST_REGOFF) = LoadFromOffset<R32W, M32>;
DEF_ISEL(LDR_32_LOADLIT) = Load<R32W, M32>;

DEF_ISEL(LDR_64_LDST_POS) = Load<R64W, M64>;
DEF_ISEL(LDR_64_LDST_IMMPOST) = LoadUpdateIndex<R64W, M64>;
DEF_ISEL(LDR_64_LDST_IMMPRE) = LoadUpdateIndex<R64W, M64>;
DEF_ISEL(LDR_64_LDST_REGOFF) = LoadFromOffset<R64W, M64>;
DEF_ISEL(LDR_64_LOADLIT) = Load<R64W, M64>;

DEF_ISEL(LDURB_32_LDST_UNSCALED) = Load<R32W, M8>;
DEF_ISEL(LDURH_32_LDST_UNSCALED) = Load<R32W, M16>;
DEF_ISEL(LDUR_32_LDST_UNSCALED) = Load<R32W, M32>;
DEF_ISEL(LDUR_64_LDST_UNSCALED) = Load<R64W, M64>;

DEF_ISEL(STURB_32_LDST_UNSCALED) = Store<R32, M8W>;
DEF_ISEL(STURH_32_LDST_UNSCALED) = Store<R32, M16W>;
DEF_ISEL(STUR_32_LDST_UNSCALED) = Store<R32, M32W>;
DEF_ISEL(STUR_64_LDST_UNSCALED) = Store<R64, M64W>;

DEF_ISEL(MOVZ_32_MOVEWIDE) = Load<R32W, I32>;
DEF_ISEL(MOVZ_64_MOVEWIDE) = Load<R64W, I64>;

namespace {

template <typename D, typename S, typename InterType>
DEF_SEM(LoadSExt, D dst, S src) {
  WriteZExt(dst, SExtTo<InterType>(Read(src)));
  return memory;
}

template <typename D, typename S, typename InterType>
DEF_SEM(LoadSExtUpdateIndex, D dst, S src, R64W dst_reg, ADDR next_addr) {
  WriteZExt(dst, SExtTo<InterType>(Read(src)));
  Write(dst_reg, Read(next_addr));
  return memory;
}

template <typename D, typename M, typename InterType>
DEF_SEM(LoadSExtFromOffset, D dst, M base, ADDR offset) {
  WriteZExt(dst, SExtTo<InterType>(Read(DisplaceAddress(base, Read(offset)))));
  return memory;
}

}  // namespace

DEF_ISEL(LDRSB_32_LDST_POS) = LoadSExt<R32W, M8, int32_t>;
DEF_ISEL(LDRSB_64_LDST_POS) = LoadSExt<R64W, M8, int64_t>;
DEF_ISEL(LDRSB_32_LDST_IMMPOST) = LoadSExtUpdateIndex<R32W, M8, int32_t>;
DEF_ISEL(LDRSB_64_LDST_IMMPOST) = LoadSExtUpdateIndex<R64W, M8, int64_t>;
DEF_ISEL(LDRSB_32_LDST_IMMPRE) = LoadSExtUpdateIndex<R32W, M8, int32_t>;
DEF_ISEL(LDRSB_64_LDST_IMMPRE) = LoadSExtUpdateIndex<R64W, M8, int64_t>;
DEF_ISEL(LDRSB_32B_LDST_REGOFF) = LoadSExtFromOffset<R32W, M8, int32_t>;
DEF_ISEL(LDRSB_32BL_LDST_REGOFF) = LoadSExtFromOffset<R32W, M8, int32_t>;
DEF_ISEL(LDRSB_64B_LDST_REGOFF) = LoadSExtFromOffset<R64W, M8, int64_t>;
DEF_ISEL(LDRSB_64BL_LDST_REGOFF) = LoadSExtFromOffset<R64W, M8, int64_t>;

DEF_ISEL(LDRSH_32_LDST_POS) = LoadSExt<R32W, M16, int32_t>;
DEF_ISEL(LDRSH_64_LDST_POS) = LoadSExt<R64W, M16, int64_t>;
DEF_ISEL(LDRSH_32_LDST_IMMPOST) = LoadSExtUpdateIndex<R32W, M16, int32_t>;
DEF_ISEL(LDRSH_64_LDST_IMMPOST) = LoadSExtUpdateIndex<R64W, M16, int64_t>;
DEF_ISEL(LDRSH_32_LDST_IMMPRE) = LoadSExtUpdateIndex<R32W, M16, int32_t>;
DEF_ISEL(LDRSH_64_LDST_IMMPRE) = LoadSExtUpdateIndex<R64W, M16, int64_t>;
DEF_ISEL(LDRSH_32_LDST_REGOFF) = LoadSExtFromOffset<R32W, M16, int32_t>;
DEF_ISEL(LDRSH_64_LDST_REGOFF) = LoadSExtFromOffset<R64W, M16, int64_t>;

DEF_ISEL(LDRSW_64_LDST_POS) = LoadSExt<R64W, M32, int64_t>;
DEF_ISEL(LDRSW_64_LDST_IMMPOST) = LoadSExtUpdateIndex<R64W, M32, int64_t>;
DEF_ISEL(LDRSW_64_LDST_IMMPRE) = LoadSExtUpdateIndex<R64W, M32, int64_t>;
DEF_ISEL(LDRSW_64_LDST_REGOFF) = LoadSExtFromOffset<R64W, M32, int64_t>;
DEF_ISEL(LDRSW_64_LOADLIT) = LoadSExt<R64W, M32, int64_t>;

namespace {

template <typename D, typename S>
DEF_SEM(MoveWithKeep, D dst, S src, I64 imm, I8 shift_) {
  auto shift = ZExtTo<uint64_t>(Read(shift_));
  auto val = UShl(Read(imm), shift);
  auto mask = UNot(UShl((0xFFFFULL), shift));
  auto reg = ZExtTo<uint64_t>(Read(src));
  WriteZExt(dst, UOr(UAnd(reg, mask), val));
  return memory;
}

DEF_SEM(FMOV_Imm32, V128W dst, F32 imm) {
  auto val = Read(imm);
  FWriteV32(dst, val);
  return memory;
}

DEF_SEM(FMOV_Imm64, V128W dst, F64 imm) {
  auto val = Read(imm);
  FWriteV64(dst, val);
  return memory;
}

DEF_SEM(FMOV_I32ToF32, V128W dst, R32 src ) {
  auto val = Read(src);
  UWriteV32(dst, val);
  return memory;
}

DEF_SEM(FMOV_F32ToI32, R32W dst, V32 src) {
  auto float_val = FExtractV32(FReadV32(src), 0);
  WriteZExt(dst, reinterpret_cast<uint32_t &>(float_val));
  return memory;
}

DEF_SEM(FMOV_I64ToF64, V128W dst, R64 src ) {
  auto val = Read(src);
  UWriteV64(dst, val);
  return memory;
}

DEF_SEM(FMOV_F64ToI64, R64W dst, V64 src) {
  auto float_val = FExtractV64(FReadV64(src), 0);
  WriteZExt(dst, reinterpret_cast<uint64_t &>(float_val));
  return memory;
}

DEF_SEM(FMOV_S, V128W dst, V32 src) {
  auto reg = FReadV32(src);
  FWriteV32(dst, reg);
  return memory;
}

DEF_SEM(FMOV_D, V128W dst, V64 src) {
  auto reg = FReadV64(src);
  FWriteV64(dst, reg);
  return memory;
}
}  // namespace

DEF_ISEL(MOVK_32_MOVEWIDE) = MoveWithKeep<R32W, R32>;
DEF_ISEL(MOVK_64_MOVEWIDE) = MoveWithKeep<R64W, R64>;

// Shifting and negating of the immediate happens in the post-decoder.
DEF_ISEL(MOVN_32_MOVEWIDE) = Load<R32W, I32>;
DEF_ISEL(MOVN_64_MOVEWIDE) = Load<R64W, I64>;

DEF_ISEL(FMOV_H_FLOATIMM) = FMOV_Imm32;
DEF_ISEL(FMOV_S_FLOATIMM) = FMOV_Imm32;
DEF_ISEL(FMOV_D_FLOATIMM) = FMOV_Imm64;

DEF_ISEL(FMOV_32S_FLOAT2INT) = FMOV_F32ToI32;
DEF_ISEL(FMOV_S32_FLOAT2INT) = FMOV_I32ToF32;

DEF_ISEL(FMOV_64D_FLOAT2INT) = FMOV_F64ToI64;
DEF_ISEL(FMOV_D64_FLOAT2INT) = FMOV_I64ToF64;

DEF_ISEL(FMOV_S_FLOATDP1) = FMOV_S;
DEF_ISEL(FMOV_D_FLOATDP1) = FMOV_D;
namespace {

DEF_SEM(ADRP, R64W dst, PC label) {
  addr_t label_addr = Read(label);

  // clear the bottom 12 bits of label_addr
  // to make this page aligned
  // the Post decoding already made the label page aligned
  // and added the label to PC
  // the semantics just needs to fix up for PC not being page aligned
  auto label_page = UAnd(UNot(static_cast<uint64_t>(4095)), label_addr);
  Write(dst, label_page);
  return memory;
}

}  // namespace

DEF_ISEL(ADRP_ONLY_PCRELADDR) = ADRP;

DEF_ISEL(ADR_ONLY_PCRELADDR) = Load<R64W, I64>;

namespace {

DEF_SEM(LDR_B, V128W dst, MV8 src) {
  UWriteV8(dst, UReadV8(src));
  return memory;
}

DEF_SEM(LDR_H, V128W dst, MV16 src) {
  UWriteV16(dst, UReadV16(src));
  return memory;
}

DEF_SEM(LDR_S, V128W dst, MV32 src) {
  FWriteV32(dst, FReadV32(src));
  return memory;
}

DEF_SEM(LDR_D, V128W dst, MV64 src) {
  FWriteV64(dst, FReadV64(src));
  return memory;
}

DEF_SEM(LDR_Q, V128W dst, MV128 src) {
  UWriteV128(dst, UReadV128(src));
  return memory;
}

DEF_SEM(LDR_B_UpdateIndex, V128W dst, MV8 src, R64W dst_reg, ADDR next_addr) {
  UWriteV8(dst, UReadV8(src));
  Write(dst_reg, Read(next_addr));
  return memory;
}

DEF_SEM(LDR_H_UpdateIndex, V128W dst, MV16 src, R64W dst_reg, ADDR next_addr) {
  UWriteV16(dst, UReadV16(src));
  Write(dst_reg, Read(next_addr));
  return memory;
}

DEF_SEM(LDR_S_UpdateIndex, V128W dst, MV32W src, R64W dst_reg, ADDR next_addr) {
  FWriteV32(dst, FReadV32(src));
  Write(dst_reg, Read(next_addr));
  return memory;
}

DEF_SEM(LDR_D_UpdateIndex, V128W dst, MV64 src, R64W dst_reg, ADDR next_addr) {
  FWriteV64(dst, FReadV64(src));
  Write(dst_reg, Read(next_addr));
  return memory;
}

DEF_SEM(LDR_Q_UpdateIndex, V128W dst, MV128 src, R64W dst_reg, ADDR next_addr) {
  UWriteV128(dst, UReadV128(src));
  Write(dst_reg, Read(next_addr));
  return memory;
}

DEF_SEM(LDR_B_FromOffset, V128W dst, MV8 src, ADDR offset) {
  UWriteV8(dst, UReadV8(DisplaceAddress(src, Read(offset))));
  return memory;
}

DEF_SEM(LDR_H_FromOffset, V128W dst, MV16 src, ADDR offset) {
  UWriteV16(dst, UReadV16(DisplaceAddress(src, Read(offset))));
  return memory;
}

DEF_SEM(LDR_S_FromOffset, V128W dst, MV32 src, ADDR offset) {
  FWriteV32(dst, FReadV32(DisplaceAddress(src, Read(offset))));
  return memory;
}

DEF_SEM(LDR_D_FromOffset, V128W dst, MV64 src, ADDR offset) {
  FWriteV64(dst, FReadV64(DisplaceAddress(src, Read(offset))));
  return memory;
}

DEF_SEM(LDR_Q_FromOffset, V128W dst, MV128 src, ADDR offset) {
  UWriteV128(dst, UReadV128(DisplaceAddress(src, Read(offset))));
  return memory;
}

}  // namespace

DEF_ISEL(LDR_B_LDST_POS) = LDR_B;
DEF_ISEL(LDR_H_LDST_POS) = LDR_H;
DEF_ISEL(LDR_S_LDST_POS) = LDR_S;
DEF_ISEL(LDR_D_LDST_POS) = LDR_D;
DEF_ISEL(LDR_Q_LDST_POS) = LDR_Q;

DEF_ISEL(LDUR_B_LDST_UNSCALED) = LDR_B;
DEF_ISEL(LDUR_H_LDST_UNSCALED) = LDR_H;
DEF_ISEL(LDUR_S_LDST_UNSCALED) = LDR_S;
DEF_ISEL(LDUR_D_LDST_UNSCALED) = LDR_D;
DEF_ISEL(LDUR_Q_LDST_UNSCALED) = LDR_Q;

DEF_ISEL(LDR_S_LOADLIT) = LDR_S;
DEF_ISEL(LDR_D_LOADLIT) = LDR_D;
DEF_ISEL(LDR_Q_LOADLIT) = LDR_Q;

DEF_ISEL(LDR_B_LDST_IMMPRE) = LDR_B_UpdateIndex;
DEF_ISEL(LDR_H_LDST_IMMPRE) = LDR_H_UpdateIndex;
DEF_ISEL(LDR_S_LDST_IMMPRE) = LDR_S_UpdateIndex;
DEF_ISEL(LDR_D_LDST_IMMPRE) = LDR_D_UpdateIndex;
DEF_ISEL(LDR_Q_LDST_IMMPRE) = LDR_Q_UpdateIndex;

DEF_ISEL(LDR_B_LDST_IMMPOST) = LDR_B_UpdateIndex;
DEF_ISEL(LDR_H_LDST_IMMPOST) = LDR_H_UpdateIndex;
DEF_ISEL(LDR_S_LDST_IMMPOST) = LDR_S_UpdateIndex;
DEF_ISEL(LDR_D_LDST_IMMPOST) = LDR_D_UpdateIndex;
DEF_ISEL(LDR_Q_LDST_IMMPOST) = LDR_Q_UpdateIndex;

DEF_ISEL(LDR_B_LDST_REGOFF) = LDR_B_FromOffset;
DEF_ISEL(LDR_H_LDST_REGOFF) = LDR_H_FromOffset;
DEF_ISEL(LDR_S_LDST_REGOFF) = LDR_S_FromOffset;
DEF_ISEL(LDR_D_LDST_REGOFF) = LDR_D_FromOffset;
DEF_ISEL(LDR_Q_LDST_REGOFF) = LDR_Q_FromOffset;

namespace {

DEF_SEM(LDP_S, V128W dst1, V128W dst2, MV64 src) {
  auto src_vec = FReadV32(src);
  FWriteV32(dst1, FExtractV32(src_vec, 0));
  FWriteV32(dst2, FExtractV32(src_vec, 1));
  return memory;
}

DEF_SEM(LDP_D, V128W dst1, V128W dst2, MV128 src) {
  auto src_vec = FReadV64(src);
  FWriteV64(dst1, FExtractV64(src_vec, 0));
  FWriteV64(dst2, FExtractV64(src_vec, 1));
  return memory;
}

DEF_SEM(LDP_Q, V128W dst1, V128W dst2, MV256 src) {
  auto src_vec = UReadV128(src);
  UWriteV128(dst1, UExtractV128(src_vec, 0));
  UWriteV128(dst2, UExtractV128(src_vec, 1));
  return memory;
}

DEF_SEM(LDP_S_UpdateIndex, V128W dst1, V128W dst2, MV64 src,
        R64W dst_reg, ADDR next_addr) {
  auto src_vec = FReadV32(src);
  FWriteV32(dst1, FExtractV32(src_vec, 0));
  FWriteV32(dst2, FExtractV32(src_vec, 1));
  Write(dst_reg, Read(next_addr));
  return memory;
}

DEF_SEM(LDP_D_UpdateIndex, V128W dst1, V128W dst2, MV128 src,
        R64W dst_reg, ADDR next_addr) {
  auto src_vec = FReadV64(src);
  FWriteV64(dst1, FExtractV64(src_vec, 0));
  FWriteV64(dst2, FExtractV64(src_vec, 1));
  Write(dst_reg, Read(next_addr));
  return memory;
}

DEF_SEM(LDP_Q_UpdateIndex, V128W dst1, V128W dst2, MV256 src,
        R64W dst_reg, ADDR next_addr) {
  auto src_vec = UReadV128(src);
  UWriteV128(dst1, UExtractV128(src_vec, 0));
  UWriteV128(dst2, UExtractV128(src_vec, 1));
  Write(dst_reg, Read(next_addr));
  return memory;
}

}  // namespace

DEF_ISEL(LDP_S_LDSTPAIR_OFF) = LDP_S;
DEF_ISEL(LDP_D_LDSTPAIR_OFF) = LDP_D;
DEF_ISEL(LDP_Q_LDSTPAIR_OFF) = LDP_Q;

DEF_ISEL(LDP_S_LDSTPAIR_POST) = LDP_S_UpdateIndex;
DEF_ISEL(LDP_D_LDSTPAIR_POST) = LDP_D_UpdateIndex;
DEF_ISEL(LDP_Q_LDSTPAIR_POST) = LDP_Q_UpdateIndex;

DEF_ISEL(LDP_S_LDSTPAIR_PRE) = LDP_S_UpdateIndex;
DEF_ISEL(LDP_D_LDSTPAIR_PRE) = LDP_D_UpdateIndex;
DEF_ISEL(LDP_Q_LDSTPAIR_PRE) = LDP_Q_UpdateIndex;

namespace {

DEF_SEM(STR_B, V8 src, MV8W dst) {
  UWriteV8(dst, UReadV8(src));
  return memory;
}

DEF_SEM(STR_H, V16 src, MV16W dst) {
  UWriteV16(dst, UReadV16(src));
  return memory;
}

DEF_SEM(STR_S, V32 src, MV32W dst) {
  FWriteV32(dst, FReadV32(src));
  return memory;
}

DEF_SEM(STR_D, V64 src, MV64W dst) {
  FWriteV64(dst, FReadV64(src));
  return memory;
}

DEF_SEM(STR_Q, V128 src, MV128W dst) {
  UWriteV128(dst, UReadV128(src));
  return memory;
}

DEF_SEM(STR_Q_UpdateIndex, V128 src, MV128W dst, R64W dst_reg, ADDR next_addr) {
  UWriteV128(dst, UReadV128(src));
  Write(dst_reg, Read(next_addr));
  return memory;
}

DEF_SEM(STR_Q_FromOffset, V128 src, MV128W dst, ADDR offset) {
  UWriteV128(DisplaceAddress(dst, Read(offset)), UReadV128(src));
  return memory;
}
}  // namespace

DEF_ISEL(STR_B_LDST_POS) = STR_B;
DEF_ISEL(STR_H_LDST_POS) = STR_H;
DEF_ISEL(STR_S_LDST_POS) = STR_S;
DEF_ISEL(STR_D_LDST_POS) = STR_D;
DEF_ISEL(STR_Q_LDST_POS) = STR_Q;

DEF_ISEL(STUR_B_LDST_UNSCALED) = STR_B;
DEF_ISEL(STUR_H_LDST_UNSCALED) = STR_H;
DEF_ISEL(STUR_S_LDST_UNSCALED) = STR_S;
DEF_ISEL(STUR_D_LDST_UNSCALED) = STR_D;
DEF_ISEL(STUR_Q_LDST_UNSCALED) = STR_Q;

DEF_ISEL(STR_Q_LDST_REGOFF) = STR_Q_FromOffset;

DEF_ISEL(STR_Q_LDST_IMMPRE) = STR_Q_UpdateIndex;

namespace {

template <typename D, typename S>
DEF_SEM(LoadAcquire, D dst, S src) {
  memory = __remill_barrier_load_store(memory);
  WriteZExt(dst, Read(src));
  return memory;
}

}  // namespace

DEF_ISEL(LDARB_LR32_LDSTEXCL) = LoadAcquire<R32W, M8>;
DEF_ISEL(LDARH_LR32_LDSTEXCL) = LoadAcquire<R32W, M16>;
DEF_ISEL(LDAR_LR32_LDSTEXCL) = LoadAcquire<R32W, M32>;
DEF_ISEL(LDAR_LR64_LDSTEXCL) = LoadAcquire<R64W, M64>;

namespace {

#define MAKE_LD1_POSTINDEX(esize) \
    template <typename S> \
    DEF_SEM(LD1_SINGLE_POSTINDEX_ ## esize, V128W dst1, S src, \
            R64W addr_reg, ADDR next_addr) { \
      auto elems1 = UReadV ## esize(src); \
      UWriteV ## esize(dst1, elems1); \
      Write(addr_reg, Read(next_addr)); \
      return memory; \
    }

MAKE_LD1_POSTINDEX(8)
MAKE_LD1_POSTINDEX(16)
MAKE_LD1_POSTINDEX(32)
MAKE_LD1_POSTINDEX(64)

#undef MAKE_LD1_POSTINDEX

}  // namespace

DEF_ISEL(LD1_ASISDLSEP_I1_I1_8B) = LD1_SINGLE_POSTINDEX_8<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I1_I1_16B) = LD1_SINGLE_POSTINDEX_8<MV128>;

DEF_ISEL(LD1_ASISDLSEP_I1_I1_4H) = LD1_SINGLE_POSTINDEX_16<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I1_I1_8H) = LD1_SINGLE_POSTINDEX_16<MV128>;

DEF_ISEL(LD1_ASISDLSEP_I1_I1_2S) = LD1_SINGLE_POSTINDEX_32<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I1_I1_4S) = LD1_SINGLE_POSTINDEX_32<MV128>;

DEF_ISEL(LD1_ASISDLSEP_I1_I1_1D) = LD1_SINGLE_POSTINDEX_64<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I1_I1_2D) = LD1_SINGLE_POSTINDEX_64<MV128>;

namespace {

#define MAKE_LD1_POSTINDEX(esize) \
    template <typename S> \
    DEF_SEM(LD1_PAIR_POSTINDEX_ ## esize, V128W dst1, V128W dst2, S src, \
            R64W addr_reg, ADDR next_addr) { \
      auto elems1 = UReadV ## esize(src); \
      auto elems2 = UReadV ## esize(GetElementPtr(src, 1U)); \
      UWriteV ## esize(dst1, elems1); \
      UWriteV ## esize(dst2, elems2); \
      Write(addr_reg, Read(next_addr)); \
      return memory; \
    }

MAKE_LD1_POSTINDEX(8)
MAKE_LD1_POSTINDEX(16)
MAKE_LD1_POSTINDEX(32)
MAKE_LD1_POSTINDEX(64)

#undef MAKE_LD1_POSTINDEX

}  // namespace

DEF_ISEL(LD1_ASISDLSEP_I2_I2_8B) = LD1_PAIR_POSTINDEX_8<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I2_I2_16B) = LD1_PAIR_POSTINDEX_8<MV128>;

DEF_ISEL(LD1_ASISDLSEP_I2_I2_4H) = LD1_PAIR_POSTINDEX_16<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I2_I2_8H) = LD1_PAIR_POSTINDEX_16<MV128>;

DEF_ISEL(LD1_ASISDLSEP_I2_I2_2S) = LD1_PAIR_POSTINDEX_32<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I2_I2_4S) = LD1_PAIR_POSTINDEX_32<MV128>;

DEF_ISEL(LD1_ASISDLSEP_I2_I2_1D) = LD1_PAIR_POSTINDEX_64<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I2_I2_2D) = LD1_PAIR_POSTINDEX_64<MV128>;

namespace {

#define MAKE_LD1_POSTINDEX(esize) \
    template <typename S> \
    DEF_SEM(LD1_TRIPLE_POSTINDEX_ ## esize, V128W dst1, V128W dst2, \
            V128W dst3, S src, R64W addr_reg, ADDR next_addr) { \
      auto elems1 = UReadV ## esize(src); \
      auto elems2 = UReadV ## esize(GetElementPtr(src, 1U)); \
      auto elems3 = UReadV ## esize(GetElementPtr(src, 2U)); \
      UWriteV ## esize(dst1, elems1); \
      UWriteV ## esize(dst2, elems2); \
      UWriteV ## esize(dst3, elems3); \
      Write(addr_reg, Read(next_addr)); \
      return memory; \
    }

MAKE_LD1_POSTINDEX(8)
MAKE_LD1_POSTINDEX(16)
MAKE_LD1_POSTINDEX(32)
MAKE_LD1_POSTINDEX(64)

#undef MAKE_LD1_POSTINDEX

}  // namespace

DEF_ISEL(LD1_ASISDLSEP_I3_I3_8B) = LD1_TRIPLE_POSTINDEX_8<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I3_I3_16B) = LD1_TRIPLE_POSTINDEX_8<MV128>;

DEF_ISEL(LD1_ASISDLSEP_I3_I3_4H) = LD1_TRIPLE_POSTINDEX_16<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I3_I3_8H) = LD1_TRIPLE_POSTINDEX_16<MV128>;

DEF_ISEL(LD1_ASISDLSEP_I3_I3_2S) = LD1_TRIPLE_POSTINDEX_32<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I3_I3_4S) = LD1_TRIPLE_POSTINDEX_32<MV128>;

DEF_ISEL(LD1_ASISDLSEP_I3_I3_1D) = LD1_TRIPLE_POSTINDEX_64<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I3_I3_2D) = LD1_TRIPLE_POSTINDEX_64<MV128>;

namespace {

#define MAKE_LD1_POSTINDEX(esize) \
    template <typename S> \
    DEF_SEM(LD1_QUAD_POSTINDEX_ ## esize, V128W dst1, V128W dst2, \
            V128W dst3, V128W dst4, S src, R64W addr_reg, ADDR next_addr) { \
      auto elems1 = UReadV ## esize(src); \
      auto elems2 = UReadV ## esize(GetElementPtr(src, 1U)); \
      auto elems3 = UReadV ## esize(GetElementPtr(src, 2U)); \
      auto elems4 = UReadV ## esize(GetElementPtr(src, 3U)); \
      UWriteV ## esize(dst1, elems1); \
      UWriteV ## esize(dst2, elems2); \
      UWriteV ## esize(dst3, elems3); \
      UWriteV ## esize(dst4, elems4); \
      Write(addr_reg, Read(next_addr)); \
      return memory; \
    }

MAKE_LD1_POSTINDEX(8)
MAKE_LD1_POSTINDEX(16)
MAKE_LD1_POSTINDEX(32)
MAKE_LD1_POSTINDEX(64)

#undef MAKE_LD1_POSTINDEX

}  // namespace

DEF_ISEL(LD1_ASISDLSEP_I4_I4_8B) = LD1_QUAD_POSTINDEX_8<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I4_I4_16B) = LD1_QUAD_POSTINDEX_8<MV128>;

DEF_ISEL(LD1_ASISDLSEP_I4_I4_4H) = LD1_QUAD_POSTINDEX_16<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I4_I4_8H) = LD1_QUAD_POSTINDEX_16<MV128>;

DEF_ISEL(LD1_ASISDLSEP_I4_I4_2S) = LD1_QUAD_POSTINDEX_32<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I4_I4_4S) = LD1_QUAD_POSTINDEX_32<MV128>;

DEF_ISEL(LD1_ASISDLSEP_I4_I4_1D) = LD1_QUAD_POSTINDEX_64<MV64>;
DEF_ISEL(LD1_ASISDLSEP_I4_I4_2D) = LD1_QUAD_POSTINDEX_64<MV128>;

namespace {

#define EXTRACT_VEC(prefix, size, ext_op) \
    template <typename D, typename T> \
    DEF_SEM(prefix ## MovFromVec ## size, D dst, V128 src, I64 index) { \
      WriteZExt(dst, ext_op<T>( \
          prefix ## ExtractV ## size( \
              prefix ## ReadV ## size(src), Read(index)))); \
      return memory; \
    } \

EXTRACT_VEC(U, 8, ZExtTo)
EXTRACT_VEC(U, 16, ZExtTo)
EXTRACT_VEC(U, 32, ZExtTo)
EXTRACT_VEC(U, 64, ZExtTo)

EXTRACT_VEC(S, 8, SExtTo)
EXTRACT_VEC(S, 16, SExtTo)
EXTRACT_VEC(S, 32, SExtTo)

#undef EXTRACT_VEC

}  // namespace

DEF_ISEL(UMOV_ASIMDINS_W_W_B) = UMovFromVec8<R32W, uint32_t>;
DEF_ISEL(UMOV_ASIMDINS_W_W_H) = UMovFromVec16<R32W, uint32_t>;
DEF_ISEL(UMOV_ASIMDINS_W_W_S) = UMovFromVec32<R32W, uint32_t>;
DEF_ISEL(UMOV_ASIMDINS_X_X_D) = UMovFromVec64<R64W, uint64_t>;

DEF_ISEL(SMOV_ASIMDINS_W_W_B) = SMovFromVec8<R32W, int32_t>;
DEF_ISEL(SMOV_ASIMDINS_W_W_H) = SMovFromVec16<R32W, int32_t>;

DEF_ISEL(SMOV_ASIMDINS_X_X_B) = SMovFromVec8<R64W, int64_t>;
DEF_ISEL(SMOV_ASIMDINS_X_X_H) = SMovFromVec16<R64W, int64_t>;
DEF_ISEL(SMOV_ASIMDINS_X_X_S) = SMovFromVec32<R64W, int64_t>;
