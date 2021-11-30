/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 */

#define MAKE_CONDITIONS(cc) \
  static inline bool CondA_##cc(const State &state) { \
    return true; \
  } \
  static inline bool CondN_##cc(const State &state) { \
    return false; \
  } \
  static inline bool CondE_##cc(const State &state) { \
    const auto ccr = state.asr.ccr.cc; \
    const bool flag_zf = ccr.z; \
    return __remill_compare_eq(flag_zf); \
  } \
  static inline bool CondNE_##cc(const State &state) { \
    const auto ccr = state.asr.ccr.cc; \
    const bool flag_zf = ccr.z; \
    return __remill_compare_neq(!flag_zf); \
  } \
  static inline bool CondG_##cc(const State &state) { \
    const auto ccr = state.asr.ccr.cc; \
    const bool flag_nf = ccr.n; \
    const bool flag_zf = ccr.z; \
    const bool flag_vf = ccr.v; \
    return __remill_compare_sgt((flag_nf == flag_vf) && !flag_zf); \
  } \
  static inline bool CondLE_##cc(const State &state) { \
    const auto ccr = state.asr.ccr.cc; \
    const bool flag_nf = ccr.n; \
    const bool flag_zf = ccr.z; \
    const bool flag_vf = ccr.v; \
    return __remill_compare_sle((flag_nf != flag_vf) || flag_zf); \
  } \
  static inline bool CondGE_##cc(const State &state) { \
    const auto ccr = state.asr.ccr.cc; \
    const bool flag_nf = ccr.n; \
    const bool flag_vf = ccr.v; \
    return __remill_compare_sge(flag_nf == flag_vf); \
  } \
  static inline bool CondL_##cc(const State &state) { \
    const auto ccr = state.asr.ccr.cc; \
    const bool flag_nf = ccr.n; \
    const bool flag_vf = ccr.v; \
    return __remill_compare_slt(flag_nf != flag_vf); \
  } \
  static inline bool CondGU_##cc(const State &state) { \
    const auto ccr = state.asr.ccr.cc; \
    const bool flag_cf = ccr.c; \
    const bool flag_zf = ccr.z; \
    return __remill_compare_ugt(!(flag_cf || flag_zf)); \
  } \
  static inline bool CondLEU_##cc(const State &state) { \
    const auto ccr = state.asr.ccr.cc; \
    const bool flag_cf = ccr.c; \
    const bool flag_zf = ccr.z; \
    return __remill_compare_ule(flag_cf || flag_zf); \
  } \
  static inline bool CondCS_##cc(const State &state) { \
    const auto ccr = state.asr.ccr.cc; \
    const bool flag_cf = ccr.c; \
    return __remill_compare_ult(flag_cf); \
  } \
  static inline bool CondCC_##cc(const State &state) { \
    const auto ccr = state.asr.ccr.cc; \
    const bool flag_cf = ccr.c; \
    return __remill_compare_uge(!flag_cf); \
  } \
  static inline bool CondPOS_##cc(const State &state) { \
    const auto ccr = state.asr.ccr.cc; \
    const bool flag_nf = ccr.n; \
    return !flag_nf; \
  } \
  static inline bool CondNEG_##cc(const State &state) { \
    const auto ccr = state.asr.ccr.cc; \
    const bool flag_nf = ccr.n; \
    return flag_nf; \
  } \
  static inline bool CondVS_##cc(const State &state) { \
    const auto ccr = state.asr.ccr.cc; \
    const bool flag_vf = ccr.v; \
    return flag_vf; \
  } \
  static inline bool CondVC_##cc(const State &state) { \
    const auto ccr = state.asr.ccr.cc; \
    const bool flag_vf = ccr.v; \
    return !flag_vf; \
  }

MAKE_CONDITIONS(xcc)
MAKE_CONDITIONS(icc)

#undef MAKE_CONDITIONS


#define MAKE_CONDITIONS(fcc) \
  static inline bool CondU_##fcc(const State &state) { \
    return (state.fsr.fcc == 0x3); \
  } \
  static inline bool CondG_##fcc(const State &state) { \
    return (state.fsr.fcc == 0x2); \
  } \
  static inline bool CondUG_##fcc(const State &state) { \
    return (state.fsr.fcc == 0x3) || (state.fsr.fcc == 0x2); \
  } \
  static inline bool CondL_##fcc(const State &state) { \
    return (state.fsr.fcc == 0x1); \
  } \
  static inline bool CondUL_##fcc(const State &state) { \
    return (state.fsr.fcc == 0x3) || (state.fsr.fcc == 0x1); \
  } \
  static inline bool CondLG_##fcc(const State &state) { \
    return (state.fsr.fcc == 0x2) || (state.fsr.fcc == 0x1); \
  } \
  static inline bool CondLGU_##fcc(const State &state) { \
    return (state.fsr.fcc == 0x3) || (state.fsr.fcc == 0x2) || \
           (state.fsr.fcc == 0x1); \
  } \
  static inline bool CondNE_##fcc(const State &state) { \
    return (state.fsr.fcc == 0x3) || (state.fsr.fcc == 0x2) || \
           (state.fsr.fcc == 0x1); \
  } \
  static inline bool CondE_##fcc(const State &state) { \
    return (state.fsr.fcc == 0x0); \
  } \
  static inline bool CondUE_##fcc(const State &state) { \
    return (state.fsr.fcc == 0x3) || (state.fsr.fcc == 0x0); \
  } \
  static inline bool CondGE_##fcc(const State &state) { \
    return (state.fsr.fcc == 0x2) || (state.fsr.fcc == 0x0); \
  } \
  static inline bool CondUGE_##fcc(const State &state) { \
    return (state.fsr.fcc == 0x3) || (state.fsr.fcc == 0x2) || \
           (state.fsr.fcc == 0x0); \
  } \
  static inline bool CondLE_##fcc(const State &state) { \
    return (state.fsr.fcc == 0x1) || (state.fsr.fcc == 0x0); \
  } \
  static inline bool CondULE_##fcc(const State &state) { \
    return (state.fsr.fcc == 0x3) || (state.fsr.fcc == 0x1) || \
           (state.fsr.fcc == 0x0); \
  } \
  static inline bool CondGLE_##fcc(const State &state) { \
    return (state.fsr.fcc == 0x2) || (state.fsr.fcc == 0x1) || \
           (state.fsr.fcc == 0x0); \
  } \
  static inline bool CondO_##fcc(const State &state) { \
    return (state.fsr.fcc == 0x2) || (state.fsr.fcc == 0x1) || \
           (state.fsr.fcc == 0x0); \
  }

MAKE_CONDITIONS(fcc0)
MAKE_CONDITIONS(fcc1)
MAKE_CONDITIONS(fcc2)
MAKE_CONDITIONS(fcc3)

template <typename T>
static inline bool CondRZ(const State &state, T cc) {
  return cc == 0;
}

template <typename T>
static inline bool CondRLEZ(const State &state, T cc) {
  return Signed(cc) <= 0;
}

template <typename T>
static inline bool CondRLZ(const State &state, T cc) {
  return Signed(cc) < 0;
}

template <typename T>
static inline bool CondRNZ(const State &state, T cc) {
  return cc != 0;
}

template <typename T>
static inline bool CondRGZ(const State &state, T cc) {
  return Signed(cc) > 0;
}

template <typename T>
static inline bool CondRGEZ(const State &state, T cc) {
  return Signed(cc) >= 0;
}

static inline bool CondA_ccc(const State &state) {
  return state.csr.ccc == 0b1000;
}

static inline bool CondN_ccc(const State &state) {
  return state.csr.ccc == 0b0000;
}

static inline bool Cond3_ccc(const State &state) {
  return state.csr.ccc == 0b0111;
}

static inline bool Cond2_ccc(const State &state) {
  return state.csr.ccc == 0b0110;
}

static inline bool Cond23_ccc(const State &state) {
  return state.csr.ccc == 0b0101;
}

static inline bool Cond1_ccc(const State &state) {
  return state.csr.ccc == 0b0100;
}

static inline bool Cond13_ccc(const State &state) {
  return state.csr.ccc == 0b0011;
}

static inline bool Cond12_ccc(const State &state) {
  return state.csr.ccc == 0b0010;
}

static inline bool Cond123_ccc(const State &state) {
  return state.csr.ccc == 0b0001;
}

static inline bool Cond0_ccc(const State &state) {
  return state.csr.ccc == 0b1001;
}

static inline bool Cond03_ccc(const State &state) {
  return state.csr.ccc == 0b1010;
}

static inline bool Cond02_ccc(const State &state) {
  return state.csr.ccc == 0b1011;
}

static inline bool Cond023_ccc(const State &state) {
  return state.csr.ccc == 0b1100;
}

static inline bool Cond01_ccc(const State &state) {
  return state.csr.ccc == 0b1101;
}

static inline bool Cond013_ccc(const State &state) {
  return state.csr.ccc == 0b1110;
}

static inline bool Cond012_ccc(const State &state) {
  return state.csr.ccc == 0b1111;
}
