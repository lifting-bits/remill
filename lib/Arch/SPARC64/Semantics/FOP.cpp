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

// Floating point Operations
namespace {

DEF_SEM(FMOVS, RF32 src, RF32W dst) {
  auto value = Read(src);
  Write(dst, value);
  WriteTrunc(FSR_CEXC, 0);
  WriteTrunc(FSR_FTT, 0);
  return memory;
}

DEF_SEM(FMOVD, RF64 src, RF64W dst) {
  Write(dst, Read(src));
  WriteTrunc(FSR_CEXC, 0);
  WriteTrunc(FSR_FTT, 0);
  return memory;
}

DEF_SEM(FMOVQ, RF64 src, RF64W dst) {
  Write(dst, Read(src));
  WriteTrunc(FSR_CEXC, 0);
  WriteTrunc(FSR_FTT, 0);
  return memory;
}

}  // namespace

DEF_ISEL(FMOVS) = FMOVS;
DEF_ISEL(FMOVD) = FMOVD;
DEF_ISEL(FMOVQ) = FMOVQ;


// Floating Point Operations
namespace {

DEF_SEM(FABSS, RF32 src, RF32W dst) {
  auto val = Read(src);
  auto result = static_cast<float32_t>(fabs(val));
  Write(dst, result);
  WriteTrunc(FSR_CEXC, 0);
  WriteTrunc(FSR_FTT, 0);
  return memory;
}

DEF_SEM(FABSD, RF64 src, RF64W dst) {
  auto val = Read(src);
  auto result = static_cast<float64_t>(fabs(val));
  Write(dst, result);
  WriteTrunc(FSR_CEXC, 0);
  WriteTrunc(FSR_FTT, 0);
  return memory;
}

DEF_SEM(FABSQ, RF64 src, RF64W dst) {
  auto val = Read(src);
  auto result = static_cast<float64_t>(fabs(val));
  Write(dst, result);
  WriteTrunc(FSR_CEXC, 0);
  WriteTrunc(FSR_FTT, 0);
  return memory;
}

DEF_SEM(FNEGS, RF32 src, RF32W dst) {
  auto val = Read(src);
  auto result = -val;
  Write(dst, result);
  WriteTrunc(FSR_CEXC, 0);
  WriteTrunc(FSR_FTT, 0);
  return memory;
}

DEF_SEM(FNEGD, RF64 src, RF64W dst) {
  auto val = Read(src);
  auto result = -val;
  Write(dst, result);
  WriteTrunc(FSR_CEXC, 0);
  WriteTrunc(FSR_FTT, 0);
  return memory;
}

DEF_SEM(FZEROS, RF32W dst) {
  uint32_t zero_i = 0U;
  auto &zero_f = reinterpret_cast<float32_t &>(zero_i);
  Write(dst, zero_f);
  return memory;
}

DEF_SEM(FZEROD, RF64W dst) {
  uint64_t zero_i = 0UL;
  auto &zero_f = reinterpret_cast<float64_t &>(zero_i);
  Write(dst, zero_f);
  return memory;
}

DEF_SEM(FONES, RF32W dst) {
  uint32_t zero_i = 0U;
  auto one_i = UNot(zero_i);
  auto &one_f = reinterpret_cast<float32_t &>(one_i);
  Write(dst, one_f);
  return memory;
}

DEF_SEM(FONED, RF64W dst) {
  uint32_t zero_i = 0U;
  auto one_i = UNot(zero_i);
  auto &one_f = reinterpret_cast<float64_t &>(one_i);
  Write(dst, one_f);
  return memory;
}

DEF_SEM(FNOT2D, RF64 src, RF64W dst) {
  auto val = Read(src);
  auto &val_i = reinterpret_cast<uint64_t &>(val);
  auto val_not = UNot(val_i);
  auto val_f = reinterpret_cast<float64_t &>(val_not);
  Write(dst, val_f);
  return memory;
}

}  // namespace

DEF_ISEL(FABSS) = FABSS;
DEF_ISEL(FABSD) = FABSD;
DEF_ISEL(FABSQ) = FABSD;

DEF_ISEL(FNEGS) = FNEGS;
DEF_ISEL(FNEGD) = FNEGD;
DEF_ISEL(FNEGQ) = FNEGD;

DEF_ISEL(FZEROS) = FZEROS;
DEF_ISEL(FZEROD) = FZEROD;

DEF_ISEL(FONES) = FONES;
DEF_ISEL(FONED) = FONED;

DEF_ISEL(FNOT2D) = FNOT2D;

namespace {

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

DEF_SEM(FsMULD, RF32 src1, RF32 src2, RF64W dst) {
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

  // Test and clear the Floating point exception and prevent
  // recording of the instructions
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

  // Test and clear the Floating point exception and prevent
  // recording of the instructions
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

}  // namespace

DEF_ISEL(FADDS) = FADDS;
DEF_ISEL(FADDD) = FADDD;

DEF_ISEL(FSUBS) = FSUBS;
DEF_ISEL(FSUBD) = FSUBD;

DEF_ISEL(FDIVS) = FDIVS;
DEF_ISEL(FDIVD) = FDIVD;

DEF_ISEL(FMULS) = FMULS;
DEF_ISEL(FMULD) = FMULD;

DEF_ISEL(FSMULD) = FsMULD;

namespace {

DEF_SEM(FSTOX, RF32 src, R64W dst) {
  WriteSExt(dst, Int64(Read(src)));
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

DEF_SEM(FDTOX, RF64 src, R64W dst) {
  WriteSExt(dst, Int64(Read(src)));
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

DEF_SEM(FITOS, RF32 src, RF32W dst) {
  Write(dst, Float32(Read(src)));
  return memory;
}

DEF_SEM(FITOD, RF32 src, RF64W dst) {
  Write(dst, Float64(Read(src)));
  return memory;
}

DEF_SEM(FXTOS, RF64 src, RF32W dst) {
  Write(dst, Float32(Read(src)));
  return memory;
}

DEF_SEM(FXTOD, RF64 src, RF64W dst) {
  Write(dst, Float64(Read(src)));
  return memory;
}

DEF_SEM(FXTOQ, RF64 src, RF64W dst) {
  Write(dst, Float64(Read(src)));
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

DEF_SEM(FSQRTS, RF32 src, RF32W dst) {
  auto lhs = Read(src);
  auto conv = Float32(__builtin_sqrtf(lhs));
  Write(dst, conv);
  return memory;
}

DEF_SEM(FSQRTD, RF64 src, RF64W dst) {
  auto lhs = Read(src);
  auto conv = Float64(__builtin_sqrt(lhs));
  Write(dst, conv);
  return memory;
}

// Copy FD[rs2] to FD[rd]
DEF_SEM(FSRC2D, RF64 src, RF64W dst) {
  Write(dst, Read(src));
  return memory;
}

DEF_SEM(FNADDD, RF64 src1, RF64 src2, RF64W dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  Write(dst, FNeg64(FAdd64(lhs, rhs)));
  return memory;
}

DEF_SEM(FNADDS, RF32 src1, RF32 src2, RF32W dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  Write(dst, FNeg32(FAdd32(lhs, rhs)));
  return memory;
}

}  // namespace

DEF_ISEL(FSTOX) = FSTOX;
DEF_ISEL(FSTOI) = FSTOI;
DEF_ISEL(FSTOD) = FSTOD;
DEF_ISEL(FSTOQ) = FSTOQ;

DEF_ISEL(FDTOX) = FDTOX;
DEF_ISEL(FDTOI) = FDTOI;

DEF_ISEL(FDTOQ) = FDTOQ;
DEF_ISEL(FDTOS) = FDTOS;

DEF_ISEL(FITOS) = FITOS;
DEF_ISEL(FITOD) = FITOD;

DEF_ISEL(FXTOS) = FXTOS;
DEF_ISEL(FXTOD) = FXTOD;
DEF_ISEL(FXTOQ) = FXTOQ;

DEF_ISEL(FSQRTS) = FSQRTS;
DEF_ISEL(FSQRTD) = FSQRTD;
DEF_ISEL(FSQRTQ) = FSQRTD;

DEF_ISEL(FQTOD) = FQTOD;
DEF_ISEL(FQTOS) = FQTOS;

DEF_ISEL(FSRC2D) = FSRC2D;

DEF_ISEL(FNADDS) = FNADDS;
DEF_ISEL(FNADDD) = FNADDD;


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
