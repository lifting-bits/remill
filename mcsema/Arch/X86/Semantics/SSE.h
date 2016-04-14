/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_X86_SEMANTICS_SSE_H_
#define MCSEMA_ARCH_X86_SEMANTICS_SSE_H_

namespace {

// TODO(pag): Ignores distinction between quiet/signalling, and ordering.
template <typename S1, typename S2>
DEF_SEM(XCOMISS, S1 src1_, S2 src2_) {
  auto src1 = R(src1_);
  auto src2 = R(src2_);

  if (src1.floats[0] > src2.floats[0]) {
    state.aflag.zf = false;
    state.aflag.pf = false;
    state.aflag.cf = false;

  } else if (src1.floats[0] < src2.floats[0]) {
    state.aflag.zf = false;
    state.aflag.pf = false;
    state.aflag.cf = true;

  } else if (src1.floats[0] == src2.floats[0]) {
    state.aflag.zf = true;
    state.aflag.pf = false;
    state.aflag.cf = false;

  } else {  // Unordered?
    state.aflag.zf = true;
    state.aflag.pf = true;
    state.aflag.cf = true;
  }

  state.aflag.of = true;
  state.aflag.sf = true;
  state.aflag.af = true;
}

// TODO(pag): Ignores distinction between quiet/signalling, and ordering.
template <typename S1, typename S2>
DEF_SEM(XCOMISD, S1 src1_, S2 src2_) {
  auto src1 = R(src1_);
  auto src2 = R(src2_);

  if (src1.doubles[0] > src2.doubles[0]) {
    state.aflag.zf = false;
    state.aflag.pf = false;
    state.aflag.cf = false;

  } else if (src1.doubles[0] < src2.doubles[0]) {
    state.aflag.zf = false;
    state.aflag.pf = false;
    state.aflag.cf = true;

  } else if (src1.doubles[0] == src2.doubles[0]) {
    state.aflag.zf = true;
    state.aflag.pf = false;
    state.aflag.cf = false;

  } else {  // Unordered?
    state.aflag.zf = true;
    state.aflag.pf = true;
    state.aflag.cf = true;
  }

  state.aflag.of = true;
  state.aflag.sf = true;
  state.aflag.af = true;
}

}  // namespace

DEF_ISEL(COMISD_XMMsd_MEMsd) = XCOMISD<V128, MV64>;
DEF_ISEL(COMISD_XMMsd_XMMsd) = XCOMISD<V128, V128>;
DEF_ISEL(COMISS_XMMss_MEMss) = XCOMISS<V128, MV64>;
DEF_ISEL(COMISS_XMMss_XMMss) = XCOMISS<V128, V128>;

DEF_ISEL(UCOMISD_XMMsd_MEMsd) = XCOMISD<V128, MV64>;
DEF_ISEL(UCOMISD_XMMsd_XMMsd) = XCOMISD<V128, V128>;
DEF_ISEL(UCOMISS_XMMss_MEMss) = XCOMISS<V128, MV64>;
DEF_ISEL(UCOMISS_XMMss_XMMss) = XCOMISS<V128, V128>;

#if HAS_FEATURE_AVX
DEF_ISEL(VCOMISD_XMMq_MEMq) = XCOMISD<V128, MV64>;
DEF_ISEL(VCOMISD_XMMq_XMMq) = XCOMISD<V128, V128>;
DEF_ISEL(VCOMISS_XMMd_MEMd) = XCOMISS<V128, MV64>;
DEF_ISEL(VCOMISS_XMMd_XMMd) = XCOMISS<V128, V128>;

DEF_ISEL(VUCOMISD_XMMdq_MEMq) = XCOMISD<V128, MV64>;
DEF_ISEL(VUCOMISD_XMMdq_XMMq) = XCOMISD<V128, V128>;
DEF_ISEL(VUCOMISS_XMMdq_MEMd) = XCOMISS<V128, MV64>;
DEF_ISEL(VUCOMISS_XMMdq_XMMd) = XCOMISS<V128, V128>;
#endif  // HAS_FEATURE_AVX

/*
88 FCOMI FCOMI_ST0_X87 X87_ALU X87 PPRO ATTRIBUTES: NOTSX
232 FCOMIP FCOMIP_ST0_X87 X87_ALU X87 PPRO ATTRIBUTES: NOTSX
1647 FUCOMI FUCOMI_ST0_X87 X87_ALU X87 PPRO ATTRIBUTES: NOTSX
1878 FUCOMIP FUCOMIP_ST0_X87 X87_ALU X87 PPRO ATTRIBUTES: NOTSX

4290 VCOMISD VCOMISD_XMMf64_XMMf64_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MXCSR SIMD_SCALAR
4291 VCOMISD VCOMISD_XMMf64_XMMf64_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MXCSR SIMD_SCALAR
4292 VCOMISD VCOMISD_XMMf64_MEMf64_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: DISP8_SCALAR MXCSR SIMD_SCALAR
4293 VCOMISS VCOMISS_XMMf32_XMMf32_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MXCSR SIMD_SCALAR
4294 VCOMISS VCOMISS_XMMf32_XMMf32_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MXCSR SIMD_SCALAR
4295 VCOMISS VCOMISS_XMMf32_MEMf32_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: DISP8_SCALAR MXCSR SIMD_SCALAR
5396 VUCOMISS VUCOMISS_XMMf32_XMMf32_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MXCSR SIMD_SCALAR
5397 VUCOMISS VUCOMISS_XMMf32_XMMf32_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MXCSR SIMD_SCALAR
5398 VUCOMISS VUCOMISS_XMMf32_MEMf32_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: DISP8_SCALAR MXCSR SIMD_SCALAR
5430 VUCOMISD VUCOMISD_XMMf64_XMMf64_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MXCSR SIMD_SCALAR
5431 VUCOMISD VUCOMISD_XMMf64_XMMf64_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MXCSR SIMD_SCALAR
5432 VUCOMISD VUCOMISD_XMMf64_MEMf64_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: DISP8_SCALAR MXCSR SIMD_SCALAR

 */

#endif  // MCSEMA_ARCH_X86_SEMANTICS_SSE_H_
