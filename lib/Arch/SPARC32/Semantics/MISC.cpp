/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 */

namespace {

DEF_SEM(NOP) {
  return memory;
}

}  // namespace

DEF_ISEL(NOP) = NOP;

#define MAKE_SEMANTICS_WR(op) \
  namespace { \
  DEF_SEM(WR##op, R32 src1, I32 src2) { \
    auto lhs = Read(src1); \
    auto rhs = Read(src2); \
    auto res = UXor(lhs, rhs); \
    WriteZExt(ASR_##op, res); \
    return memory; \
  } \
  } \
  DEF_ISEL(WR##op) = WR##op;

MAKE_SEMANTICS_WR(Y)
MAKE_SEMANTICS_WR(PAUSE)
MAKE_SEMANTICS_WR(STICK_CMPR)
MAKE_SEMANTICS_WR(SOFTINT)
MAKE_SEMANTICS_WR(FPRS)
MAKE_SEMANTICS_WR(GSR)
MAKE_SEMANTICS_WR(ASI)

#define MAKE_SEMANTICS_RD(op) \
  namespace { \
  DEF_SEM(RD##op, R32W dst) { \
    auto asr = Read(ASR_##op); \
    Write(dst, asr); \
    return memory; \
  } \
  } \
  DEF_ISEL(RD##op) = RD##op;

MAKE_SEMANTICS_RD(Y)
MAKE_SEMANTICS_RD(ASI)
MAKE_SEMANTICS_RD(PC)
MAKE_SEMANTICS_RD(FPRS)

namespace {

DEF_SEM(IMPDEP1, I32 opf) {
  HYPER_CALL_VECTOR = Literal<decltype(state.hyper_call_vector)>(Read(opf));
  return __remill_sync_hyper_call(
      state, memory,
      SyncHyperCall::IF_32BIT_ELSE(kSPARC32EmulateInstruction,
                                   kSPARC64EmulateInstruction));
}

DEF_SEM(IMPDEP2, I32 opf) {
  HYPER_CALL_VECTOR = Literal<decltype(state.hyper_call_vector)>(Read(opf));
  return __remill_sync_hyper_call(
      state, memory,
      SyncHyperCall::IF_32BIT_ELSE(kSPARC32EmulateInstruction,
                                   kSPARC64EmulateInstruction));
}

}  // namespace
DEF_ISEL(IMPDEP1) = IMPDEP1;
DEF_ISEL(IMPDEP2) = IMPDEP2;
