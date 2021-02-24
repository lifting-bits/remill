/*
 * Copyright (c) 2019 Trail of Bits, Inc.
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

template <typename S, typename D>
DEF_SEM(ST, S src, D dst) {
  WriteZExt(dst, Read(src));
  return memory;
}

template <typename S, typename D>
DEF_SEM(STA, R8 asi, S src, D dst) {
  WriteZExt(dst, Read(src));
  HYPER_CALL_VECTOR = Read(asi);
  return __remill_sync_hyper_call(state, memory,
                                  SyncHyperCall::kSPARCSetAsiRegister);
}

DEF_SEM(STF, RF32 src, MF32W dst) {
  auto lhs = Read(src);
  Write(dst, lhs);
  return memory;
}

DEF_SEM(STDF, RF64 src, MF64W dst) {
  auto lhs = Read(src);
  Write(dst, lhs);
  return memory;
}

DEF_SEM(STFA, R8 asi, RF32 src, MF32W dst) {
  auto lhs = Read(src);
  Write(dst, lhs);
  HYPER_CALL_VECTOR = Read(asi);
  return __remill_sync_hyper_call(state, memory,
                                  SyncHyperCall::kSPARCSetAsiRegister);
}

DEF_SEM(STDFA, R8 asi, RF64 src, MF64W dst) {
  auto lhs = Read(src);
  Write(dst, lhs);
  HYPER_CALL_VECTOR = Read(asi);
  return __remill_sync_hyper_call(state, memory,
                                  SyncHyperCall::kSPARCSetAsiRegister);
}

DEF_SEM(STTW_R32, R32 src1, R32 src2, MV64W dst) {
  auto value_index0 = Read(src1);
  auto value_index1 = Read(src2);
  auto dst_vec = UClearV32(UReadV32(dst));
  dst_vec = UInsertV32(dst_vec, 0, value_index0);
  dst_vec = UInsertV32(dst_vec, 1, value_index1);
  UWriteV32(dst, dst_vec);
  return memory;
}

DEF_SEM(STTW_IMM, R32 src1, R32 src2, MV64W dst) {
  auto value_index0 = Read(src1);
  auto value_index1 = Read(src2);
  auto dst_vec = UClearV32(UReadV32(dst));
  dst_vec = UInsertV32(dst_vec, 0, value_index0);
  dst_vec = UInsertV32(dst_vec, 1, value_index1);
  UWriteV32(dst, dst_vec);
  return memory;
}

template <typename S, typename D>
DEF_SEM(SETHI, S src, D dst) {
  const auto high_bits = Read(src);
  Write(dst, high_bits);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(SET, S1 src1, S2 src2, D dst) {
  const auto high_bits = Read(src1);
  const auto low_bits = Read(src2);
  Write(dst, UOr(high_bits, low_bits));
  return memory;
}

template <typename S1, typename S2, typename D1, typename D2>
DEF_SEM(SETHI_OR, S1 src1, S2 src2, D1 dst1, D2 dst2) {
  const auto high_bits = Read(src1);
  const auto low_bits = Read(src2);
  Write(dst1, high_bits);
  Write(dst2, UOr(high_bits, low_bits));
  return memory;
}

template <typename S1, typename S2, typename D1, typename D2>
DEF_SEM(SETHI_ADD, S1 src1, S2 src2, D1 dst1, D2 dst2) {
  const auto high_bits = Read(src1);
  const auto low_bits = Read(src2);
  Write(dst1, high_bits);
  Write(dst2, UAdd(high_bits, low_bits));
  return memory;
}

}  // namespace

DEF_ISEL(STB) = ST<R8, M8W>;
DEF_ISEL(STH) = ST<R16, M16W>;
DEF_ISEL(STW) = ST<R32, M32W>;
DEF_ISEL(STX) = ST<R64, M64W>;

DEF_ISEL(STBA) = STA<R8, M8W>;
DEF_ISEL(STHA) = STA<R16, M16W>;
DEF_ISEL(STWA) = STA<R32, M32W>;
DEF_ISEL(STXA) = STA<R64, M64W>;

DEF_ISEL(STF) = STF;
DEF_ISEL(STDF) = STDF;
DEF_ISEL(STQF) = STDF;

DEF_ISEL(STFA) = STFA;
DEF_ISEL(STDFA) = STDFA;
DEF_ISEL(STQFA) = STDFA;

DEF_ISEL(SETHI) = SETHI<I64, R64W>;
DEF_ISEL(SET) = SET<I64, I64, R64W>;
DEF_ISEL(SETHI_OR) = SETHI_OR<I64, I64, R64W, R64W>;
DEF_ISEL(SETHI_ADD) = SETHI_ADD<R64, R64, R64W, R64W>;

DEF_ISEL(STTW_R32EXCL) = STTW_R32;
DEF_ISEL(STTW_IMMEXC) = STTW_IMM;

namespace {

template <typename S, typename D>
DEF_SEM(LDU, S src, D dst) {
  WriteZExt(dst, Read(src));
  return memory;
}

template <typename S, typename D>
DEF_SEM(LDUA, R8 asi, S src, D dst) {
  WriteZExt(dst, Read(src));
  HYPER_CALL_VECTOR = Read(asi);
  return __remill_sync_hyper_call(state, memory,
                                  SyncHyperCall::kSPARCSetAsiRegister);
}

template <typename S, typename D>
DEF_SEM(LDS, S src, D dst) {
  WriteSExt(dst, Signed(Read(src)));
  return memory;
}

template <typename S, typename D>
DEF_SEM(LDSA, R8 asi, S src, D dst) {
  WriteSExt(dst, Signed(Read(src)));
  HYPER_CALL_VECTOR = Read(asi);
  return __remill_sync_hyper_call(state, memory,
                                  SyncHyperCall::kSPARCSetAsiRegister);
}

DEF_SEM(LDF, MV64 src, R32W dst) {
  auto vec = UReadV32(src);
  WriteZExt(dst, UExtractV32(vec, 0));
  return memory;
}

DEF_SEM(LDDF, MV64 src, R64W dst) {
  auto vec = UReadV64(src);
  WriteZExt(dst, UExtractV64(vec, 0));
  return memory;
}

DEF_SEM(LDFA, R8 asi, MV64 src, R32W dst) {
  auto vec = UReadV32(src);
  WriteZExt(dst, UExtractV32(vec, 0));
  HYPER_CALL_VECTOR = Read(asi);
  return __remill_sync_hyper_call(state, memory,
                                  SyncHyperCall::kSPARCSetAsiRegister);
}

DEF_SEM(LDDFA, R8 asi, MV64 src, R64W dst) {
  auto vec = UReadV64(src);
  WriteZExt(dst, UExtractV64(vec, 0));
  HYPER_CALL_VECTOR = Read(asi);
  return __remill_sync_hyper_call(state, memory,
                                  SyncHyperCall::kSPARCSetAsiRegister);
}

DEF_SEM(LDTW_IMMEXC, MV64 src_mem, R32W dst1, R32W dst2) {
  auto value1 = UExtractV32(UReadV32(src_mem), 0);
  auto value2 = UExtractV32(UReadV32(src_mem), 1);
  WriteZExt(dst1, value1);
  WriteZExt(dst2, value2);
  return memory;
}

DEF_SEM(LDTW_R32EXC, MV64 src_mem, R32W dst1, R32W dst2) {
  auto value1 = UExtractV32(UReadV32(src_mem), 0);
  auto value2 = UExtractV32(UReadV32(src_mem), 1);
  WriteZExt(dst1, value1);
  WriteZExt(dst2, value2);
  return memory;
}

}  // namespace

DEF_ISEL(LDUB) = LDU<M8, R64W>;
DEF_ISEL(LDUH) = LDU<M16, R64W>;
DEF_ISEL(LDUW) = LDU<M32, R64W>;
DEF_ISEL(LDX) = LDU<M64, R64W>;

DEF_ISEL(LDUBA) = LDUA<M8, R64W>;
DEF_ISEL(LDUHA) = LDUA<M16, R64W>;
DEF_ISEL(LDUWA) = LDUA<M32, R64W>;
DEF_ISEL(LDXA) = LDUA<M64, R64W>;

DEF_ISEL(LDSB) = LDS<M8, R64W>;
DEF_ISEL(LDSH) = LDS<M16, R64W>;
DEF_ISEL(LDSW) = LDS<M32, R64W>;

DEF_ISEL(LDSBA) = LDSA<M8, R64W>;
DEF_ISEL(LDSHA) = LDSA<M16, R64W>;
DEF_ISEL(LDSWA) = LDSA<M32, R64W>;

DEF_ISEL(LDF) = LDF;
DEF_ISEL(LDDF) = LDDF;
DEF_ISEL(LDQF) = LDDF;

DEF_ISEL(LDFA) = LDFA;
DEF_ISEL(LDDFA) = LDDFA;
DEF_ISEL(LDQFA) = LDDFA;

DEF_ISEL(LDTW_IMMEXC) = LDTW_IMMEXC;
DEF_ISEL(LDTW_R32EXC) = LDTW_R32EXC;

namespace {

template <typename R>
DEF_SEM(LDSTUB, M8W src_mem, R dst) {
  auto mem_val = Read(src_mem);
  WriteZExt(dst, mem_val);
  Write(src_mem, static_cast<uint8_t>(0xffu));
  return memory;
}

template <typename R>
DEF_SEM(LDSTUBA, R8 asi, M8W src_mem, R dst) {
  auto mem_val = Read(src_mem);
  WriteZExt(dst, mem_val);
  Write(src_mem, static_cast<uint8_t>(0xffu));
  return __remill_sync_hyper_call(state, memory,
                                  SyncHyperCall::kSPARCSetAsiRegister);
}

DEF_SEM(CASA, R32 src1, R32 src2, R32W dst) {
  uint32_t rs2 = Read(src2);
  addr_t addr = Read(src1);
  auto addr_rs1 = ReadPtr<uint32_t>(addr);
  uint32_t value_rs1 = Read(addr_rs1);
  if (value_rs1 == rs2) {
    Write(WritePtr<uint32_t>(addr), Read(dst));
  }
  Write(dst, value_rs1);
  return memory;
}

DEF_SEM(SWAP, M32W src, R64W dst) {
  auto old_dst = Read(dst);
  auto old_src = Read(src);
  WriteZExt(dst, old_src);
  WriteTrunc(src, old_dst);
  return memory;
}

DEF_SEM(SWAPA, R8 asi, M32W src, R64W dst) {
  auto old_dst = Read(dst);
  auto old_src = Read(src);
  WriteZExt(dst, old_src);
  WriteTrunc(src, old_dst);
  HYPER_CALL_VECTOR = Read(asi);
  return __remill_sync_hyper_call(state, memory,
                                  SyncHyperCall::kSPARCSetAsiRegister);
}

}  // namespace

DEF_ISEL(LDSTUB) = LDSTUB<R64W>;
DEF_ISEL(LDSTUBA) = LDSTUBA<R64W>;
DEF_ISEL(CASA) = CASA;
DEF_ISEL(SWAP) = SWAP;
DEF_ISEL(SWAPA) = SWAPA;

namespace {

template <typename S, typename D>
DEF_SEM(MOVA_icc, S src, D dst) {
  WriteZExt(dst, Read(src));
  return memory;
}
template <typename S, typename D>
DEF_SEM(MOVA_xcc, S src, D dst) {
  WriteZExt(dst, Read(src));
  return memory;
}

template <typename S, typename D>
DEF_SEM(MOVN_icc, S src, D dst) {
  return memory;
}
template <typename S, typename D>
DEF_SEM(MOVN_xcc, S src, D dst) {
  return memory;
}

}  // namespace

DEF_ISEL(MOVA_icc) = MOVA_icc<R64, R64W>;
DEF_ISEL(MOVA_xcc) = MOVA_xcc<R64, R64W>;
DEF_ISEL(MOVN_icc) = MOVN_icc<R64, R64W>;
DEF_ISEL(MOVN_xcc) = MOVN_xcc<R64, R64W>;

#define MAKE_SEMANTICS(name, cond, cc) \
  namespace { \
  template <typename S, typename D> \
  DEF_SEM(name##cond##_##cc, S src, D dst) { \
    auto new_value = Read(src); \
    auto old_value = Read(dst); \
    auto branch_taken = Cond##cond##_##cc(state); \
    auto value = \
        Select(branch_taken, new_value, decltype(new_value)(old_value)); \
    WriteZExt(dst, value); \
    return memory; \
  } \
  } \
  DEF_ISEL(MOV##cond##_##cc) = name##cond##_##cc<R64, R64W>;

#define MAKE_SEMANTICS_CC(name, cond) \
  MAKE_SEMANTICS(name, cond, icc) \
  MAKE_SEMANTICS(name, cond, xcc)

#define MAKE_SEMANTICS_FCC(name, cond) \
  MAKE_SEMANTICS(name, cond, fcc0) \
  MAKE_SEMANTICS(name, cond, fcc1) \
  MAKE_SEMANTICS(name, cond, fcc2) \
  MAKE_SEMANTICS(name, cond, fcc3)


MAKE_SEMANTICS_CC(MOV, NE)
MAKE_SEMANTICS_CC(MOV, E)
MAKE_SEMANTICS_CC(MOV, G)
MAKE_SEMANTICS_CC(MOV, LE)
MAKE_SEMANTICS_CC(MOV, GE)
MAKE_SEMANTICS_CC(MOV, L)
MAKE_SEMANTICS_CC(MOV, GU)
MAKE_SEMANTICS_CC(MOV, LEU)
MAKE_SEMANTICS_CC(MOV, CC)
MAKE_SEMANTICS_CC(MOV, CS)
MAKE_SEMANTICS_CC(MOV, POS)
MAKE_SEMANTICS_CC(MOV, NEG)
MAKE_SEMANTICS_CC(MOV, VC)
MAKE_SEMANTICS_CC(MOV, VS)

MAKE_SEMANTICS_FCC(MOVF, U)
MAKE_SEMANTICS_FCC(MOVF, G)
MAKE_SEMANTICS_FCC(MOVF, UG)
MAKE_SEMANTICS_FCC(MOVF, L)
MAKE_SEMANTICS_FCC(MOVF, UL)
MAKE_SEMANTICS_FCC(MOVF, LG)
MAKE_SEMANTICS_FCC(MOVF, NE)
MAKE_SEMANTICS_FCC(MOVF, E)
MAKE_SEMANTICS_FCC(MOVF, UE)
MAKE_SEMANTICS_FCC(MOVF, GE)
MAKE_SEMANTICS_FCC(MOVF, UGE)
MAKE_SEMANTICS_FCC(MOVF, LE)
MAKE_SEMANTICS_FCC(MOVF, ULE)
MAKE_SEMANTICS_FCC(MOVF, O)

#undef MAKE_SEMANTICS
#undef MAKE_SEMANTICS_CC
#undef MAKE_SEMANTICS_FCC

#define MAKE_SEMANTICS(name, cond) \
  namespace { \
  template <typename C, typename S, typename D> \
  DEF_SEM(name##cond, C reg_cc, S src, D dst) { \
    auto new_value = Read(src); \
    auto old_value = Read(dst); \
    auto cc = Read(reg_cc); \
    auto cond_taken = CondR##cond(state, cc); \
    auto value = \
        Select(cond_taken, new_value, decltype(new_value)(old_value)); \
    WriteZExt(dst, value); \
    return memory; \
  } \
  } \
  DEF_ISEL(name##cond) = name##cond<R64, R64, R64W>;

MAKE_SEMANTICS(MOVR, Z)
MAKE_SEMANTICS(MOVR, LEZ)
MAKE_SEMANTICS(MOVR, LZ)
MAKE_SEMANTICS(MOVR, NZ)
MAKE_SEMANTICS(MOVR, GZ)
MAKE_SEMANTICS(MOVR, GEZ)

#undef MAKE_SEMANTICS

namespace {

DEF_SEM(FMoveAlwaysSingle, RF32 src, RF32W dst) {
  auto new_val = Read(src);
  Write(dst, new_val);
  WriteTrunc(FSR_CEXC, 0);
  WriteTrunc(FSR_FTT, 0);
  return memory;
}

DEF_SEM(FMoveNeverSingle, RF32 src, RF32W dst) {
  return memory;
}

DEF_SEM(FMoveAlwaysDouble, RF64 src, RF64W dst) {
  auto new_val = Read(src);
  Write(dst, new_val);
  WriteTrunc(FSR_CEXC, 0);
  WriteTrunc(FSR_FTT, 0);
  return memory;
}

DEF_SEM(FMoveNeverDouble, RF64 src, RF64W dst) {
  return memory;
}

DEF_SEM(FMoveAlwaysQuad, RF64 src, RF64W dst) {
  auto new_val = Read(src);
  Write(dst, new_val);
  WriteTrunc(FSR_CEXC, 0);
  WriteTrunc(FSR_FTT, 0);
  return memory;
}

DEF_SEM(FMoveNeverQuad, RF64 src, RF64W dst) {
  return memory;
}

}  // namespace

DEF_ISEL(FMOVSA_icc) = FMoveAlwaysSingle;
DEF_ISEL(FMOVSA_xcc) = FMoveAlwaysSingle;
DEF_ISEL(FMOVSA_fcc0) = FMoveAlwaysSingle;
DEF_ISEL(FMOVSA_fcc1) = FMoveAlwaysSingle;
DEF_ISEL(FMOVSA_fcc2) = FMoveAlwaysSingle;
DEF_ISEL(FMOVSA_fcc3) = FMoveAlwaysSingle;

DEF_ISEL(FMOVSN_icc) = FMoveNeverSingle;
DEF_ISEL(FMOVSN_xcc) = FMoveNeverSingle;
DEF_ISEL(FMOVSN_fcc0) = FMoveNeverSingle;
DEF_ISEL(FMOVSN_fcc1) = FMoveNeverSingle;
DEF_ISEL(FMOVSN_fcc2) = FMoveNeverSingle;
DEF_ISEL(FMOVSN_fcc3) = FMoveNeverSingle;

DEF_ISEL(FMOVDA_icc) = FMoveAlwaysDouble;
DEF_ISEL(FMOVDA_xcc) = FMoveAlwaysDouble;
DEF_ISEL(FMOVDA_fcc0) = FMoveAlwaysDouble;
DEF_ISEL(FMOVDA_fcc1) = FMoveAlwaysDouble;
DEF_ISEL(FMOVDA_fcc2) = FMoveAlwaysDouble;
DEF_ISEL(FMOVDA_fcc3) = FMoveAlwaysDouble;

DEF_ISEL(FMOVDN_icc) = FMoveNeverDouble;
DEF_ISEL(FMOVDN_xcc) = FMoveNeverDouble;
DEF_ISEL(FMOVDN_fcc0) = FMoveNeverDouble;
DEF_ISEL(FMOVDN_fcc1) = FMoveNeverDouble;
DEF_ISEL(FMOVDN_fcc2) = FMoveNeverDouble;
DEF_ISEL(FMOVDN_fcc3) = FMoveNeverDouble;

DEF_ISEL(FMOVQA_icc) = FMoveAlwaysQuad;
DEF_ISEL(FMOVQA_xcc) = FMoveAlwaysQuad;
DEF_ISEL(FMOVQA_fcc0) = FMoveAlwaysQuad;
DEF_ISEL(FMOVQA_fcc1) = FMoveAlwaysQuad;
DEF_ISEL(FMOVQA_fcc2) = FMoveAlwaysQuad;
DEF_ISEL(FMOVQA_fcc3) = FMoveAlwaysQuad;

DEF_ISEL(FMOVQN_icc) = FMoveNeverQuad;
DEF_ISEL(FMOVQN_xcc) = FMoveNeverQuad;
DEF_ISEL(FMOVQN_fcc0) = FMoveNeverQuad;
DEF_ISEL(FMOVQN_fcc1) = FMoveNeverQuad;
DEF_ISEL(FMOVQN_fcc2) = FMoveNeverQuad;
DEF_ISEL(FMOVQN_fcc3) = FMoveNeverQuad;


#define MAKE_SEMANTICS(name, cond, cc) \
  namespace { \
  DEF_SEM(FMOVS##cond##_##cc, RF32 src, RF32W dst) { \
    auto new_val = Read(src); \
    auto old_val = Read(dst); \
    auto branch_taken = Cond##cond##_##cc(state); \
    auto value = Select(branch_taken, new_val, decltype(new_val)(old_val)); \
    Write(dst, value); \
    WriteTrunc(FSR_CEXC, 0); \
    WriteTrunc(FSR_FTT, 0); \
    return memory; \
  } \
  DEF_SEM(FMOVD##cond##_##cc, RF64 src, RF64W dst) { \
    auto new_val = Read(src); \
    auto old_val = Read(dst); \
    auto branch_taken = Cond##cond##_##cc(state); \
    auto value = Select(branch_taken, new_val, decltype(new_val)(old_val)); \
    Write(dst, value); \
    WriteTrunc(FSR_CEXC, 0); \
    WriteTrunc(FSR_FTT, 0); \
    return memory; \
  } \
  DEF_SEM(FMOVQ##cond##_##cc, RF64 src, RF64W dst) { \
    auto new_val = Read(src); \
    auto old_val = Read(dst); \
    auto branch_taken = Cond##cond##_##cc(state); \
    auto value = Select(branch_taken, new_val, decltype(new_val)(old_val)); \
    Write(dst, value); \
    WriteTrunc(FSR_CEXC, 0); \
    WriteTrunc(FSR_FTT, 0); \
    return memory; \
  } \
  } \
  DEF_ISEL(FMOVS##cond##_##cc) = FMOVS##cond##_##cc; \
  DEF_ISEL(FMOVD##cond##_##cc) = FMOVD##cond##_##cc; \
  DEF_ISEL(FMOVQ##cond##_##cc) = FMOVQ##cond##_##cc;

#define MAKE_SEMANTICS_CC(name, cond) \
  MAKE_SEMANTICS(name, cond, icc) \
  MAKE_SEMANTICS(name, cond, xcc)

#define MAKE_SEMANTICS_FCC(name, cond) \
  MAKE_SEMANTICS(name, cond, fcc0) \
  MAKE_SEMANTICS(name, cond, fcc1) \
  MAKE_SEMANTICS(name, cond, fcc2) \
  MAKE_SEMANTICS(name, cond, fcc3)

MAKE_SEMANTICS_CC(FMOV, NE)
MAKE_SEMANTICS_CC(FMOV, E)
MAKE_SEMANTICS_CC(FMOV, G)
MAKE_SEMANTICS_CC(FMOV, LE)
MAKE_SEMANTICS_CC(FMOV, GE)
MAKE_SEMANTICS_CC(FMOV, L)
MAKE_SEMANTICS_CC(FMOV, GU)
MAKE_SEMANTICS_CC(FMOV, LEU)
MAKE_SEMANTICS_CC(FMOV, CC)
MAKE_SEMANTICS_CC(FMOV, CS)
MAKE_SEMANTICS_CC(FMOV, POS)
MAKE_SEMANTICS_CC(FMOV, NEG)
MAKE_SEMANTICS_CC(FMOV, VC)
MAKE_SEMANTICS_CC(FMOV, VS)

MAKE_SEMANTICS_FCC(FMOV, U)
MAKE_SEMANTICS_FCC(FMOV, G)
MAKE_SEMANTICS_FCC(FMOV, UG)
MAKE_SEMANTICS_FCC(FMOV, L)
MAKE_SEMANTICS_FCC(FMOV, UL)
MAKE_SEMANTICS_FCC(FMOV, LG)
MAKE_SEMANTICS_FCC(FMOV, NE)
MAKE_SEMANTICS_FCC(FMOV, E)
MAKE_SEMANTICS_FCC(FMOV, UE)
MAKE_SEMANTICS_FCC(FMOV, GE)
MAKE_SEMANTICS_FCC(FMOV, UGE)
MAKE_SEMANTICS_FCC(FMOV, LE)
MAKE_SEMANTICS_FCC(FMOV, ULE)
MAKE_SEMANTICS_FCC(FMOV, O)

#undef MAKE_SEMANTICS
#undef MAKE_SEMANTICS_CC
#undef MAKE_SEMANTICS_FCC

#define MAKE_SEMANTICS(name, cond) \
  namespace { \
  DEF_SEM(name##S##cond, R64 reg_cc, V32 src, V32W dst) { \
    auto new_val = FExtractV32(FReadV32(src), 0); \
    auto old_val = FExtractV32(FReadV32(dst), 0); \
    auto cc = Read(reg_cc); \
    auto cond_taken = CondR##cond(state, cc); \
    auto value = Select(cond_taken, new_val, decltype(new_val)(old_val)); \
    FWriteV32(dst, value); \
    WriteTrunc(FSR_CEXC, 0); \
    WriteTrunc(FSR_FTT, 0); \
    return memory; \
  } \
  DEF_SEM(name##D##cond, R64 reg_cc, V64 src, V64W dst) { \
    auto new_val = FExtractV64(FReadV64(src), 0); \
    auto old_val = FExtractV64(FReadV64(dst), 0); \
    auto cc = Read(reg_cc); \
    auto cond_taken = CondR##cond(state, cc); \
    auto value = Select(cond_taken, new_val, decltype(new_val)(old_val)); \
    FWriteV64(dst, value); \
    WriteTrunc(FSR_CEXC, 0); \
    WriteTrunc(FSR_FTT, 0); \
    return memory; \
  } \
  DEF_SEM(name##Q##cond, R64 reg_cc, V64 src, V64W dst) { \
    auto new_val = FExtractV64(FReadV64(src), 0); \
    auto old_val = FExtractV64(FReadV64(dst), 0); \
    auto cc = Read(reg_cc); \
    auto cond_taken = CondR##cond(state, cc); \
    auto value = Select(cond_taken, new_val, decltype(new_val)(old_val)); \
    FWriteV64(dst, value); \
    WriteTrunc(FSR_CEXC, 0); \
    WriteTrunc(FSR_FTT, 0); \
    return memory; \
  } \
  } \
  DEF_ISEL(name##S##cond) = name##S##cond; \
  DEF_ISEL(name##D##cond) = name##D##cond; \
  DEF_ISEL(name##Q##cond) = name##Q##cond;

MAKE_SEMANTICS(FMOVR, Z)
MAKE_SEMANTICS(FMOVR, LEZ)
MAKE_SEMANTICS(FMOVR, LZ)
MAKE_SEMANTICS(FMOVR, NZ)
MAKE_SEMANTICS(FMOVR, GZ)
MAKE_SEMANTICS(FMOVR, GEZ)
