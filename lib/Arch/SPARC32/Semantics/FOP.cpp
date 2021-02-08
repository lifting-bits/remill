/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 */

namespace {

// Floating point operations
DEF_SEM(FADDS, RF32 src1, RF32 src2, RF32W dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);

  // Test and clear the Floating point exception and prevent
  // recording of the instructions
  auto old_except = __remill_fpu_exception_test_and_clear(0, FE_ALL_EXCEPT);
  BarrierReorder();
  auto sum = FAdd(lhs, rhs);
  BarrierReorder();
  auto new_except =
      __remill_fpu_exception_test_and_clear(FE_ALL_EXCEPT, old_except);
  SetFPSRStatusFlags(state, new_except);
  Write(dst, sum);
  return memory;
}

DEF_SEM(FADDD, RF64 src1, RF64 src2, RF64W dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);

  // Test and clear the Floating point exception and prevent
  // recording of the instructions
  auto old_except = __remill_fpu_exception_test_and_clear(0, FE_ALL_EXCEPT);
  BarrierReorder();
  auto sum = FAdd64(lhs, rhs);
  BarrierReorder();
  auto new_except =
      __remill_fpu_exception_test_and_clear(FE_ALL_EXCEPT, old_except);
  SetFPSRStatusFlags(state, new_except);
  Write(dst, sum);
  return memory;
}

DEF_SEM(FSUBS, RF32 src1, RF32 src2, RF32W dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);

  // Test and clear the Floating point exception and prevent
  // recording of the instructions
  auto old_except = __remill_fpu_exception_test_and_clear(0, FE_ALL_EXCEPT);
  BarrierReorder();
  auto sub = FSub32(lhs, rhs);
  BarrierReorder();
  auto new_except =
      __remill_fpu_exception_test_and_clear(FE_ALL_EXCEPT, old_except);
  SetFPSRStatusFlags(state, new_except);
  Write(dst, sub);
  return memory;
}

DEF_SEM(FSUBD, RF64 src1, RF64 src2, RF64W dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);

  // Test and clear the Floating point exception and prevent
  // recording of the instructions
  auto old_except = __remill_fpu_exception_test_and_clear(0, FE_ALL_EXCEPT);
  BarrierReorder();
  auto sub = FSub64(lhs, rhs);
  BarrierReorder();
  auto new_except =
      __remill_fpu_exception_test_and_clear(FE_ALL_EXCEPT, old_except);
  SetFPSRStatusFlags(state, new_except);
  Write(dst, sub);
  return memory;
}

DEF_SEM(FMULS, RF32 src1, RF32 src2, RF32W dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);

  // Test and clear the Floating point exception and prevent
  // recording of the instructions
  auto old_except = __remill_fpu_exception_test_and_clear(0, FE_ALL_EXCEPT);
  BarrierReorder();
  auto mul = FMul32(lhs, rhs);
  BarrierReorder();
  auto new_except =
      __remill_fpu_exception_test_and_clear(FE_ALL_EXCEPT, old_except);
  SetFPSRStatusFlags(state, new_except);
  Write(dst, mul);
  return memory;
}

DEF_SEM(FMULD, RF64 src1, RF64 src2, RF64W dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);

  // Test and clear the Floating point exception and prevent
  // recording of the instructions
  auto old_except = __remill_fpu_exception_test_and_clear(0, FE_ALL_EXCEPT);
  BarrierReorder();
  auto mul = FMul64(lhs, rhs);
  BarrierReorder();
  auto new_except =
      __remill_fpu_exception_test_and_clear(FE_ALL_EXCEPT, old_except);
  SetFPSRStatusFlags(state, new_except);
  Write(dst, mul);
  return memory;
}

DEF_SEM(FDIVS, RF32 src1, RF32 src2, RF32W dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);

  // Test and clear the fp exception and prevent recording
  auto old_except = __remill_fpu_exception_test_and_clear(0, FE_ALL_EXCEPT);
  BarrierReorder();
  auto div = FDiv32(lhs, rhs);
  BarrierReorder();
  auto new_except =
      __remill_fpu_exception_test_and_clear(FE_ALL_EXCEPT, old_except);
  SetFPSRStatusFlags(state, new_except);
  Write(dst, div);
  return memory;
}

DEF_SEM(FDIVD, RF64 src1, RF64 src2, RF64W dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);

  // Test and clear the fp exception and prevent recording
  auto old_except = __remill_fpu_exception_test_and_clear(0, FE_ALL_EXCEPT);
  BarrierReorder();
  auto div = FDiv64(lhs, rhs);
  BarrierReorder();
  auto new_except =
      __remill_fpu_exception_test_and_clear(FE_ALL_EXCEPT, old_except);
  SetFPSRStatusFlags(state, new_except);
  Write(dst, div);
  return memory;
}

DEF_SEM(FsMULD, RF32 src1, RF32 src2, RF64W dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);

  // Test and clear the fp exception and prevent recording
  auto old_except = __remill_fpu_exception_test_and_clear(0, FE_ALL_EXCEPT);
  BarrierReorder();
  auto mul = FMul64(lhs, rhs);
  BarrierReorder();
  auto new_except =
      __remill_fpu_exception_test_and_clear(FE_ALL_EXCEPT, old_except);
  SetFPSRStatusFlags(state, new_except);
  Write(dst, mul);
  return memory;
}

DEF_SEM(FdMULQ, RF64 src1, RF64 src2, RF64W dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);

  // Test and clear the fp exception and prevent recording
  auto old_except = __remill_fpu_exception_test_and_clear(0, FE_ALL_EXCEPT);
  BarrierReorder();
  auto mul = FMul64(lhs, rhs);
  BarrierReorder();
  auto new_except =
      __remill_fpu_exception_test_and_clear(FE_ALL_EXCEPT, old_except);
  SetFPSRStatusFlags(state, new_except);
  Write(dst, mul);
  return memory;
}

}  // namespace

DEF_ISEL(FADDS) = FADDS;
DEF_ISEL(FADDD) = FADDD;
DEF_ISEL(FADDQ) = FADDD;

DEF_ISEL(FSUBS) = FSUBS;
DEF_ISEL(FSUBD) = FSUBD;
DEF_ISEL(FSUBQ) = FSUBD;

DEF_ISEL(FMULS) = FMULS;
DEF_ISEL(FMULD) = FMULD;
DEF_ISEL(FMULQ) = FMULD;

DEF_ISEL(FDIVS) = FDIVS;
DEF_ISEL(FDIVD) = FDIVD;
DEF_ISEL(FDIVQ) = FDIVD;

DEF_ISEL(FSMULD) = FsMULD;
DEF_ISEL(FDMULQ) = FdMULQ;

namespace {

DEF_SEM(FMOVS, RF32 src, RF32W dst) {
  auto value = Read(src);
  Write(dst, value);
  WriteTrunc(FSR_CEXC, 0);
  WriteTrunc(FSR_FTT, 0);
  return memory;
}

DEF_SEM(FMOVD, RF64 src, RF64W dst) {
  auto value = Read(src);
  Write(dst, value);
  WriteTrunc(FSR_CEXC, 0);
  WriteTrunc(FSR_FTT, 0);
  return memory;
}

DEF_SEM(FABSS, RF32 src, RF32W dst) {
  auto value = Read(src);
  auto result = static_cast<float32_t>(fabs(value));
  Write(dst, result);
  WriteTrunc(FSR_CEXC, 0);
  WriteTrunc(FSR_FTT, 0);
  return memory;
}

DEF_SEM(FABSD, RF64 src, RF64W dst) {
  auto value = Read(src);
  auto result = static_cast<float64_t>(fabs(value));
  Write(dst, result);
  WriteTrunc(FSR_CEXC, 0);
  WriteTrunc(FSR_FTT, 0);
  return memory;
}

DEF_SEM(FNEGS, RF32 src, RF32W dst) {
  auto value = Read(src);
  auto result = -value;
  Write(dst, result);
  WriteTrunc(FSR_CEXC, 0);
  WriteTrunc(FSR_FTT, 0);
  return memory;
}

DEF_SEM(FNEGD, RF64 src, RF64W dst) {
  auto value = Read(src);
  auto result = -value;
  Write(dst, result);
  WriteTrunc(FSR_CEXC, 0);
  WriteTrunc(FSR_FTT, 0);
  return memory;
}

DEF_SEM(FSQRTS, RF32 src, RF32W dst) {
  auto value = Read(src);
  auto res = Float32(__builtin_sqrtf(value));
  Write(dst, res);
  return memory;
}

DEF_SEM(FSQRTD, RF64 src, RF64W dst) {
  auto lhs = Read(src);
  auto res = Float64(__builtin_sqrt(lhs));
  Write(dst, res);
  return memory;
}

DEF_SEM(FITOS, R32 src, RF32W dst) {
  Write(dst, Float32(Read(src)));
  return memory;
}

DEF_SEM(FITOD, R32 src, RF64W dst) {
  Write(dst, Float64(Read(src)));
  return memory;
}

DEF_SEM(FSTOI, RF32 src, R32W dst) {
  WriteSExt(dst, Int32(Read(src)));
  return memory;
}

DEF_SEM(FSTOD, RF32 src, RF64W dst) {
  Write(dst, Float64(Read(src)));
  return memory;
}

DEF_SEM(FSTOQ, RF32 src, RF64W dst) {
  Write(dst, Float64(Read(src)));
  return memory;
}

DEF_SEM(FDTOI, RF64 src, R32W dst) {
  WriteSExt(dst, Int32(Read(src)));
  return memory;
}

DEF_SEM(FDTOQ, RF64 src, RF64W dst) {
  Write(dst, Read(src));
  return memory;
}

DEF_SEM(FDTOS, RF64 src, RF32W dst) {
  Write(dst, Float32(Read(src)));
  return memory;
}

DEF_SEM(FQTOD, RF64 src, RF64W dst) {
  Write(dst, Float64(Read(src)));
  return memory;
}

DEF_SEM(FQTOS, RF64 src, RF32W dst) {
  Write(dst, Float32(Read(src)));
  return memory;
}

DEF_SEM(FXTOS, R64 src, RF32W dst) {
  Write(dst, Float32(Read(src)));
  return memory;
}

DEF_SEM(FXTOD, R64 src, RF64W dst) {
  Write(dst, Float64(Read(src)));
  return memory;
}

DEF_SEM(FXTOQ, R64 src, RF64W dst) {
  Write(dst, Float64(Read(src)));
  return memory;
}

DEF_SEM(FDTOX, RF64 src, R64W dst) {
  WriteSExt(dst, Int64(Read(src)));
  return memory;
}

DEF_SEM(FSTOX, RF32 src, R64W dst) {
  WriteSExt(dst, Int64(Read(src)));
  return memory;
}

}  // namespace

DEF_ISEL(FMOVS) = FMOVS;
DEF_ISEL(FMOVD) = FMOVD;
DEF_ISEL(FMOVQ) = FMOVD;

DEF_ISEL(FABSS) = FABSS;
DEF_ISEL(FABSD) = FABSD;
DEF_ISEL(FABSQ) = FABSD;

DEF_ISEL(FNEGS) = FNEGS;
DEF_ISEL(FNEGD) = FNEGD;
DEF_ISEL(FNEGQ) = FNEGD;

DEF_ISEL(FSQRTS) = FSQRTS;
DEF_ISEL(FSQRTD) = FSQRTD;
DEF_ISEL(FSQRTQ) = FSQRTD;

DEF_ISEL(FITOS) = FITOS;
DEF_ISEL(FITOD) = FITOD;
DEF_ISEL(FITOQ) = FITOD;

DEF_ISEL(FSTOI) = FSTOI;
DEF_ISEL(FSTOD) = FSTOD;
DEF_ISEL(FSTOQ) = FSTOQ;
DEF_ISEL(FSTOX) = FSTOX;

DEF_ISEL(FDTOI) = FDTOI;
DEF_ISEL(FDTOS) = FDTOS;
DEF_ISEL(FDTOQ) = FDTOQ;
DEF_ISEL(FDTOX) = FDTOX;

DEF_ISEL(FQTOS) = FDTOS;
DEF_ISEL(FQTOD) = FQTOD;

DEF_ISEL(FXTOS) = FXTOS;
DEF_ISEL(FXTOD) = FXTOD;
DEF_ISEL(FXTOQ) = FXTOQ;


#define MAKE_COMPARE(fcc) \
  template <typename S> \
  void FCompare_##fcc(State &state, Memory *memory, S val1, S val2, \
                      bool signal) { \
    if (std::isnan(val1) || std::isnan(val2)) { \
      Write(state.fsr.fcc, Literal<R8>(3)); \
    } else { \
      if (FCmpEq(val1, val2)) { \
        /* result = '00'; */ \
        Write(state.fsr.fcc, Literal<R8>(0)); \
      } else if (FCmpLt(val1, val2)) { \
        /* result = '01'; */ \
        Write(state.fsr.fcc, Literal<R8>(1)); \
      } else { /* FCmpGt(val1, val2) */ \
        /* result = '10'; */ \
        Write(state.fsr.fcc, Literal<R8>(2)); \
      } \
    } \
  }


namespace {

MAKE_COMPARE(fcc0)
MAKE_COMPARE(fcc1)
MAKE_COMPARE(fcc2)
MAKE_COMPARE(fcc3)

}  // namespace

#undef MAKE_COMPARE

#define MAKE_SEMANTICS_FCMP(fcc) \
  DEF_SEM(FCMPS_##fcc, RF32 src1, RF32 src2) { \
    auto val1 = Read(src1); \
    auto val2 = Read(src2); \
    FCompare_##fcc(state, memory, val1, val2, false); \
    return memory; \
  } \
\
  DEF_SEM(FCMPD_##fcc, RF64 src1, RF64 src2) { \
    auto val1 = Read(src1); \
    auto val2 = Read(src2); \
    FCompare_##fcc(state, memory, val1, val2, false); \
    return memory; \
  } \
\
  DEF_SEM(FCMPQ_##fcc, RF64 src1, RF64 src2) { \
    auto val1 = Read(src1); \
    auto val2 = Read(src2); \
    FCompare_##fcc(state, memory, val1, val2, false); \
    return memory; \
  }

#define MAKE_SEMANTICS_FCMPE(fcc) \
  DEF_SEM(FCMPES_##fcc, RF32 src1, RF32 src2) { \
    auto val1 = Read(src1); \
    auto val2 = Read(src2); \
    FCompare_##fcc(state, memory, val1, val2, false); \
    return memory; \
  } \
\
  DEF_SEM(FCMPED_##fcc, RF64 src1, RF64 src2) { \
    auto val1 = Read(src1); \
    auto val2 = Read(src2); \
    FCompare_##fcc(state, memory, val1, val2, false); \
    return memory; \
  } \
\
  DEF_SEM(FCMPEQ_##fcc, RF64 src1, RF64 src2) { \
    auto val1 = Read(src1); \
    auto val2 = Read(src2); \
    FCompare_##fcc(state, memory, val1, val2, false); \
    return memory; \
  }

namespace {

MAKE_SEMANTICS_FCMP(fcc0)
MAKE_SEMANTICS_FCMP(fcc1)
MAKE_SEMANTICS_FCMP(fcc2)
MAKE_SEMANTICS_FCMP(fcc3)

MAKE_SEMANTICS_FCMPE(fcc0)
MAKE_SEMANTICS_FCMPE(fcc1)
MAKE_SEMANTICS_FCMPE(fcc2)
MAKE_SEMANTICS_FCMPE(fcc3)

}  // namespace

#undef MAKE_SEMANTICS_FCMP
#undef MAKE_SEMANTICS_FCMPE

DEF_ISEL(FCMPS_fcc0) = FCMPS_fcc0;
DEF_ISEL(FCMPD_fcc0) = FCMPD_fcc0;
DEF_ISEL(FCMPQ_fcc0) = FCMPQ_fcc0;

DEF_ISEL(FCMPS_fcc1) = FCMPS_fcc1;
DEF_ISEL(FCMPD_fcc1) = FCMPD_fcc1;
DEF_ISEL(FCMPQ_fcc1) = FCMPQ_fcc1;

DEF_ISEL(FCMPS_fcc2) = FCMPS_fcc2;
DEF_ISEL(FCMPD_fcc2) = FCMPD_fcc2;
DEF_ISEL(FCMPQ_fcc2) = FCMPQ_fcc2;

DEF_ISEL(FCMPS_fcc3) = FCMPS_fcc3;
DEF_ISEL(FCMPD_fcc3) = FCMPD_fcc3;
DEF_ISEL(FCMPQ_fcc3) = FCMPQ_fcc3;

DEF_ISEL(FCMPES_fcc0) = FCMPES_fcc0;
DEF_ISEL(FCMPED_fcc0) = FCMPED_fcc0;
DEF_ISEL(FCMPEQ_fcc0) = FCMPEQ_fcc0;

DEF_ISEL(FCMPES_fcc1) = FCMPES_fcc1;
DEF_ISEL(FCMPED_fcc1) = FCMPED_fcc1;
DEF_ISEL(FCMPEQ_fcc1) = FCMPEQ_fcc1;

DEF_ISEL(FCMPES_fcc2) = FCMPES_fcc2;
DEF_ISEL(FCMPED_fcc2) = FCMPED_fcc2;
DEF_ISEL(FCMPEQ_fcc2) = FCMPEQ_fcc2;

DEF_ISEL(FCMPES_fcc3) = FCMPES_fcc3;
DEF_ISEL(FCMPED_fcc3) = FCMPED_fcc3;
DEF_ISEL(FCMPEQ_fcc3) = FCMPEQ_fcc3;
