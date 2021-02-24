/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 */

namespace {

template <typename S1>
DEF_SEM(LDU, S1 src, R32W dst) {
  WriteZExt(dst, Read(src));
  return memory;
}

template <typename S1>
DEF_SEM(LDS, S1 src, R32W dst) {
  WriteSExt(dst, Read(src));
  return memory;
}

template <typename S1>
DEF_SEM(LDF, S1 src, R32W dst) {
  WriteZExt(dst, Read(src));
  return memory;
}

DEF_SEM(LDD, M32 src1, M32 src2, R32W dst1, R32W dst2) {
  Write(dst1, Read(src1));
  Write(dst2, Read(src2));
  return memory;
}

template <typename S1, typename D>
DEF_SEM(ST, S1 src, D dst) {
  WriteZExt(dst, Read(src));
  return memory;
}

DEF_SEM(STD, R32 src1, R32 src2, M32W dst1, M32W dst2) {
  Write(dst1, Read(src1));
  Write(dst2, Read(src2));
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

DEF_ISEL(LDSB) = LDS<M8>;
DEF_ISEL(LDUB) = LDU<M8>;
DEF_ISEL(LDSH) = LDS<M16>;
DEF_ISEL(LDUH) = LDU<M16>;
DEF_ISEL(LD) = LDU<M32>;
DEF_ISEL(LDD) = LDD;
DEF_ISEL(LDF) = LDF<M32>;
DEF_ISEL(LDDF) = LDD;

DEF_ISEL(STB) = ST<R8, M8W>;
DEF_ISEL(STH) = ST<R16, M16W>;
DEF_ISEL(ST) = ST<R32, M32W>;
DEF_ISEL(STD) = STD;
DEF_ISEL(STX) = ST<R32, M32W>;

DEF_ISEL(STF) = ST<R32, M32W>;
DEF_ISEL(STDF) = STD;

DEF_ISEL(SETHI) = SETHI<I32, R32W>;
DEF_ISEL(SET) = SET<I32, I32, R32W>;
DEF_ISEL(SETHI_OR) = SETHI_OR<I32, I32, R32W, R32W>;
DEF_ISEL(SETHI_ADD) = SETHI_ADD<I32, I32, R32W, R32W>;

namespace {

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

DEF_SEM(CASAX, R32 src1, R32 src2, R32W dst) {
  uint32_t rs2 = Read(src2);
  addr_t addr = Read(src1);
  auto addr_rs1 = ReadPtr<uint32_t>(addr);
  uint32_t value_rs1 = Read(addr_rs1);
  if (value_rs1 == rs2) {
    Write(WritePtr<uint32_t>(addr), Read(dst));
  }
  WriteZExt(dst, value_rs1);
  return memory;
}

DEF_SEM(SWAP, M32W addr, R32W rd) {
  auto old_addr = Read(addr);
  auto old_rd = Read(rd);
  WriteZExt(addr, old_rd);
  WriteZExt(rd, old_addr);
  return memory;
}

template <typename R>
DEF_SEM(LDSTUB, M8W src_mem, R dst) {
  auto mem_val = Read(src_mem);
  WriteZExt(dst, mem_val);
  Write(src_mem, static_cast<uint8_t>(0xffu));
  return memory;
}

}  // namespace

DEF_ISEL(CASA) = CASA;
DEF_ISEL(CASAX) = CASAX;
DEF_ISEL(SWAP) = SWAP;
DEF_ISEL(LDSTUB) = LDSTUB<R32W>;

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

DEF_ISEL(MOVA_icc) = MOVA_icc<R32, R32W>;
DEF_ISEL(MOVA_xcc) = MOVA_xcc<R32, R32W>;
DEF_ISEL(MOVN_icc) = MOVN_icc<R32, R32W>;
DEF_ISEL(MOVN_xcc) = MOVN_xcc<R32, R32W>;


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
  DEF_ISEL(MOV##cond##_##cc) = name##cond##_##cc<R32, R32W>;

#define MAKE_SEMANTICS_CC(name, cond) \
  MAKE_SEMANTICS(name, cond, icc) \
  MAKE_SEMANTICS(name, cond, xcc)

#define MAKE_SEMANTICS_FCC(name, cond) \
  MAKE_SEMANTICS(name, cond, fcc0) \
  MAKE_SEMANTICS(name, cond, fcc1) \
  MAKE_SEMANTICS(name, cond, fcc2) \
  MAKE_SEMANTICS(name, cond, fcc3)


namespace {

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

}  // namespace

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
  DEF_ISEL(MOVR##cond) = name##cond<R32, R32, R32W>;

MAKE_SEMANTICS(MOVR, Z)
MAKE_SEMANTICS(MOVR, LEZ)
MAKE_SEMANTICS(MOVR, LZ)
MAKE_SEMANTICS(MOVR, NZ)
MAKE_SEMANTICS(MOVR, GZ)
MAKE_SEMANTICS(MOVR, GEZ)

#undef MAKE_SEMANTICS

namespace {

DEF_SEM(FMoveAlwaysSingle, V32 src, V32W dst) {
  auto new_val = FExtractV32(FReadV32(src), 0);
  FWriteV32(dst, new_val);
  WriteTrunc(FSR_CEXC, 0);
  WriteTrunc(FSR_FTT, 0);
  return memory;
}

DEF_SEM(FMoveNeverSingle, V32 src, V32W dst) {
  return memory;
}

DEF_SEM(FMoveAlwaysDouble, V64 src, V64W dst) {
  auto new_val = FExtractV64(FReadV64(src), 0);
  FWriteV64(dst, new_val);
  WriteTrunc(FSR_CEXC, 0);
  WriteTrunc(FSR_FTT, 0);
  return memory;
}

DEF_SEM(FMoveNeverDouble, V64 src, V64W dst) {
  return memory;
}

DEF_SEM(FMoveAlwaysQuad, V64 src, V64W dst) {
  auto new_val = FExtractV64(FReadV64(src), 0);
  FWriteV64(dst, new_val);
  WriteTrunc(FSR_CEXC, 0);
  WriteTrunc(FSR_FTT, 0);
  return memory;
}

DEF_SEM(FMoveNeverQuad, V64 src, V64W dst) {
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
  DEF_SEM(FMOVS##cond##_##cc, V32 src, V32W dst) { \
    auto new_val = FExtractV32(FReadV32(src), 0); \
    auto old_val = FExtractV32(FReadV32(dst), 0); \
    auto branch_taken = Cond##cond##_##cc(state); \
    auto value = Select(branch_taken, new_val, decltype(new_val)(old_val)); \
    FWriteV32(dst, value); \
    WriteTrunc(FSR_CEXC, 0); \
    WriteTrunc(FSR_FTT, 0); \
    return memory; \
  } \
  DEF_SEM(FMOVD##cond##_##cc, V64 src, V64W dst) { \
    auto new_val = FExtractV64(FReadV64(src), 0); \
    auto old_val = FExtractV64(FReadV64(dst), 0); \
    auto branch_taken = Cond##cond##_##cc(state); \
    auto value = Select(branch_taken, new_val, decltype(new_val)(old_val)); \
    FWriteV64(dst, value); \
    WriteTrunc(FSR_CEXC, 0); \
    WriteTrunc(FSR_FTT, 0); \
    return memory; \
  } \
  DEF_SEM(FMOVQ##cond##_##cc, V64 src, V64W dst) { \
    auto new_val = FExtractV64(FReadV64(src), 0); \
    auto old_val = FExtractV64(FReadV64(dst), 0); \
    auto branch_taken = Cond##cond##_##cc(state); \
    auto value = Select(branch_taken, new_val, decltype(new_val)(old_val)); \
    FWriteV64(dst, value); \
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
  DEF_SEM(name##S##cond, R32 reg_cc, V32 src, V32W dst) { \
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
  DEF_SEM(name##D##cond, R32 reg_cc, V64 src, V64W dst) { \
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
  DEF_SEM(name##Q##cond, R32 reg_cc, V64 src, V64W dst) { \
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
