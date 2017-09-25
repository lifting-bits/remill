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

}  // namespace

DEF_ISEL(STP_32_LDSTPAIR_PRE) = StorePairUpdateIndex32;
DEF_ISEL(STP_32_LDSTPAIR_POST) = StorePairUpdateIndex32;

DEF_ISEL(STP_64_LDSTPAIR_PRE) = StorePairUpdateIndex64;
DEF_ISEL(STP_64_LDSTPAIR_POST) = StorePairUpdateIndex64;

namespace {

template <typename S, typename D>
DEF_SEM(StoreUpdateIndex, S src, D dst_mem, R64W dst_reg, ADDR next_addr) {
  Write(dst_mem, Read(src));
  Write(dst_reg, Read(next_addr));
  return memory;
}

template <typename S, typename D>
DEF_SEM(Store, S src, D dst) {
  Write(dst, Read(src));
  return memory;
}

template <typename S, typename D>
DEF_SEM(STR_BASE_OFFSET, S src, D base, ADDR offset) {
  Write(DisplaceAddress(base, Read(offset)), Read(src));
  return memory;
}

}  // namespace

DEF_ISEL(STR_32_LDST_IMMPRE) = StoreUpdateIndex<R32, M32W>;
DEF_ISEL(STR_32_LDST_IMMPOST) = StoreUpdateIndex<R32, M32W>;

DEF_ISEL(STR_64_LDST_IMMPRE) = StoreUpdateIndex<R64, M64W>;
DEF_ISEL(STR_64_LDST_IMMPOST) = StoreUpdateIndex<R64, M64W>;

DEF_ISEL(STR_32_LDST_POS) = Store<R32, M32W>;
DEF_ISEL(STR_64_LDST_POS) = Store<R64, M64W>;

DEF_ISEL(STRB_32_LDST_POS) = Store<R8, M8W>;
DEF_ISEL(STRH_32_LDST_POS) = Store<R16, M16W>;

DEF_ISEL(STR_32_LDST_REGOFF) = STR_BASE_OFFSET<R32, M32W>;
DEF_ISEL(STR_64_LDST_REGOFF) = STR_BASE_OFFSET<R64, M64W>;

namespace {

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

}  // namespace

DEF_ISEL(STP_32_LDSTPAIR_OFF) = StorePair32;
DEF_ISEL(STP_64_LDSTPAIR_OFF) = StorePair64;

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

template <typename D, typename M>
DEF_SEM(LDR_BASE_OFFSET, D dst, M base, ADDR offset) {
  WriteZExt(dst, Read(DisplaceAddress(base, Read(offset))));
  return memory;
}

}  // namespace

DEF_ISEL(LDR_32_LDST_POS) = Load<R32W, M32>;
DEF_ISEL(LDR_64_LDST_POS) = Load<R64W, M64>;
DEF_ISEL(LDRB_32_LDST_POS) = Load<R8W, M8>;

DEF_ISEL(LDR_32_LOADLIT) = Load<R32W, M32>;
DEF_ISEL(LDR_64_LOADLIT) = Load<R64W, M64>;

DEF_ISEL(LDR_32_LDST_REGOFF) = LDR_BASE_OFFSET<R32W, M32>;
DEF_ISEL(LDR_64_LDST_REGOFF) = LDR_BASE_OFFSET<R64W, M64>;

DEF_ISEL(LDUR_32_LDST_UNSCALED) = Load<R32W, M32>;
DEF_ISEL(LDUR_64_LDST_UNSCALED) = Load<R64W, M64>;

//DEF_ISEL(MOV_ADD_32_ADDSUB_IMM) = Load<R32W, R32>;
//DEF_ISEL(MOV_ADD_64_ADDSUB_IMM) = Load<R64W, R64>;
//
//DEF_ISEL(MOV_ORR_32_LOG_SHIFT) = Load<R32W, R32>;
//DEF_ISEL(MOV_ORR_64_LOG_SHIFT) = Load<R64W, R64>;
//
//DEF_ISEL(MOV_ORR_32_LOG_IMM) = Load<R32W, I32>;
//DEF_ISEL(MOV_ORR_64_LOG_IMM) = Load<R64W, I64>;
//
//DEF_ISEL(MOV_MOVZ_32_MOVEWIDE) = Load<R32W, I32>;
//DEF_ISEL(MOV_MOVZ_64_MOVEWIDE) = Load<R64W, I64>;
//
//DEF_ISEL(MOV_MOVN_32_MOVEWIDE) = Load<R32W, I32>;
//DEF_ISEL(MOV_MOVN_64_MOVEWIDE) = Load<R64W, I64>;

DEF_ISEL(MOVZ_32_MOVEWIDE) = Load<R32W, I32>;
DEF_ISEL(MOVZ_64_MOVEWIDE) = Load<R64W, I64>;

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

}  // namespace

DEF_ISEL(MOVK_32_MOVEWIDE) = MoveWithKeep<R32W, R32>;
DEF_ISEL(MOVK_64_MOVEWIDE) = MoveWithKeep<R64W, R64>;

// Shifting and negating of the immediate happens in the post-decoder.
DEF_ISEL(MOVN_32_MOVEWIDE) = Load<R32W, I32>;
DEF_ISEL(MOVN_64_MOVEWIDE) = Load<R64W, I64>;

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

}  // namespace

DEF_ISEL(STR_B_LDST_POS) = STR_B;
DEF_ISEL(STR_H_LDST_POS) = STR_H;
DEF_ISEL(STR_S_LDST_POS) = STR_S;
DEF_ISEL(STR_D_LDST_POS) = STR_D;
DEF_ISEL(STR_Q_LDST_POS) = STR_Q;
