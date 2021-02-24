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

// Disable the "loop not unrolled warnings"
#pragma clang diagnostic ignored "-Wpass-failed"

namespace {

enum FloatCompareOperator {
  kEqOrderedQuiet,
  kLtOrderedSignal,
  kLeOrderedSignal,
  kUnorderedQuiet,
  kNeUnorderedQuiet,
  kNltUnorderedSignal,
  kNleUnorderedSignal,
  kOrderedQuiet,
  kEqUnorderedQuiet,
  kNgeUnorderedSignal,
  kNgtUnorderedSignal,
  kFalseOrderedQuiet,
  kNeOrderedQuiet,
  kGeOrderedSignal,
  kGtOrderedSignal,
  kTrueUnorderedQuiet,
  kEqOrderedSignal,
  kLtOrderedQuiet,
  kLeOrderedQuiet,
  kUnorderedSignal,
  kNeUnorderedSignal,
  kNltUnorderedQuiet,
  kNleUnorderedQuiet,
  kOrderedSignal,
  kEqUnorderedSignal,
  kNgeUnorderedQuiet,
  kNgtUnorderedQuiet,
  kFalseOrderedSignal,
  kNeOrderedSignal,
  kGeOrderedQuiet,
  kGtOrderedQuiet,
  kTrueUnorderedSignal,
};

template <typename T>
ALWAYS_INLINE static bool CompareFloats(FloatCompareOperator op, T v1, T v2) {
  auto is_unordered = __builtin_isunordered(v1, v2);
  auto is_ordered = !is_unordered;
  switch (op) {
    case kEqOrderedQuiet: return !__builtin_islessgreater(v1, v2) && is_ordered;
    case kLtOrderedSignal: return v1 < v2 && is_ordered;
    case kLeOrderedSignal: return v1 <= v2 && is_ordered;
    case kUnorderedQuiet: return is_unordered;
    case kNeUnorderedQuiet:
      return __builtin_islessgreater(v1, v2) || is_unordered;
    case kNltUnorderedSignal: return !(v1 < v2) || is_unordered;
    case kNleUnorderedSignal: return !(v1 <= v2) || is_unordered;
    case kOrderedQuiet: return is_ordered;
    case kEqUnorderedQuiet: return !__builtin_islessgreater(v1, v2);
    case kNgeUnorderedSignal: return !(v1 >= v2) || is_unordered;
    case kNgtUnorderedSignal: return !(v1 > v2) || is_unordered;
    case kFalseOrderedQuiet: return false;
    case kNeOrderedQuiet: return __builtin_islessgreater(v1, v2);
    case kGeOrderedSignal: return v1 >= v2 && is_ordered;
    case kGtOrderedSignal: return v1 > v2 && is_ordered;
    case kTrueUnorderedQuiet: return true;
    case kEqOrderedSignal: return v1 == v2 && is_ordered;
    case kLtOrderedQuiet: return __builtin_isless(v1, v2);
    case kLeOrderedQuiet: return __builtin_islessequal(v1, v2);
    case kUnorderedSignal: return is_unordered;
    case kNeUnorderedSignal: return v1 != v2 || is_unordered;
    case kNltUnorderedQuiet: return !__builtin_isless(v1, v2);
    case kNleUnorderedQuiet: return !__builtin_islessequal(v1, v2);
    case kOrderedSignal: return is_ordered;
    case kEqUnorderedSignal: return v1 == v2 || is_unordered;
    case kNgeUnorderedQuiet: return !__builtin_isgreaterequal(v1, v2);
    case kNgtUnorderedQuiet: return !__builtin_isgreater(v1, v2);
    case kFalseOrderedSignal: return false;
    case kNeOrderedSignal: return !(v1 == v2) && is_ordered;
    case kGeOrderedQuiet: return __builtin_isgreaterequal(v1, v2);
    case kGtOrderedQuiet: return __builtin_isgreater(v1, v2);
    case kTrueUnorderedSignal: return true;
  }
}

template <typename S1, typename S2>
DEF_SEM(COMISS, S1 src1, S2 src2) {
  auto left = FExtractV32(FReadV32(src1), 0);
  auto right = FExtractV32(FReadV32(src2), 0);

  if (__builtin_isunordered(left, right)) {
    if (IsSignalingNaN(left + right)) {
      StopFailure();
    }

    Write(FLAG_ZF, true);
    Write(FLAG_PF, true);
    Write(FLAG_CF, true);

  } else if (FCmpGt(left, right)) {
    Write(FLAG_ZF, false);
    Write(FLAG_PF, false);
    Write(FLAG_CF, false);
  } else if (FCmpLt(left, right)) {
    Write(FLAG_ZF, false);
    Write(FLAG_PF, false);
    Write(FLAG_CF, true);

  } else if (FCmpEq(left, right)) {
    Write(FLAG_ZF, true);
    Write(FLAG_PF, false);
    Write(FLAG_CF, false);
  }

  Write(FLAG_OF, false);
  Write(FLAG_SF, false);
  Write(FLAG_AF, false);
  return memory;
}

template <typename S1, typename S2>
DEF_SEM(COMISD, S1 src1, S2 src2) {
  auto left = FExtractV64(FReadV64(src1), 0);
  auto right = FExtractV64(FReadV64(src2), 0);

  if (__builtin_isunordered(left, right)) {
    if (IsSignalingNaN(left + right)) {
      StopFailure();
    }

    Write(FLAG_ZF, true);
    Write(FLAG_PF, true);
    Write(FLAG_CF, true);

  } else if (FCmpGt(left, right)) {
    Write(FLAG_ZF, false);
    Write(FLAG_PF, false);
    Write(FLAG_CF, false);
  } else if (FCmpLt(left, right)) {
    Write(FLAG_ZF, false);
    Write(FLAG_PF, false);
    Write(FLAG_CF, true);

  } else if (FCmpEq(left, right)) {
    Write(FLAG_ZF, true);
    Write(FLAG_PF, false);
    Write(FLAG_CF, false);
  }
  Write(FLAG_OF, false);
  Write(FLAG_SF, false);
  Write(FLAG_AF, false);
  return memory;
}

}  // namespace

DEF_ISEL(COMISD_XMMsd_MEMsd) = COMISD<V128, MV64>;
DEF_ISEL(COMISD_XMMsd_XMMsd) = COMISD<V128, V128>;
DEF_ISEL(COMISS_XMMss_MEMss) = COMISS<V128, MV32>;
DEF_ISEL(COMISS_XMMss_XMMss) = COMISS<V128, V128>;

#if HAS_FEATURE_AVX
DEF_ISEL(VCOMISD_XMMq_MEMq) = COMISD<V128, MV64>;
DEF_ISEL(VCOMISD_XMMq_XMMq) = COMISD<V128, V128>;
DEF_ISEL(VCOMISS_XMMd_MEMd) = COMISS<V128, MV32>;
DEF_ISEL(VCOMISS_XMMd_XMMd) = COMISS<V128, V128>;
#endif  // HAS_FEATURE_AVX

DEF_ISEL(UCOMISD_XMMsd_MEMsd) = COMISD<V128, MV64>;
DEF_ISEL(UCOMISD_XMMsd_XMMsd) = COMISD<V128, V128>;
DEF_ISEL(UCOMISS_XMMss_MEMss) = COMISS<V128, MV32>;
DEF_ISEL(UCOMISS_XMMss_XMMss) = COMISS<V128, V128>;

#if HAS_FEATURE_AVX
DEF_ISEL(VUCOMISD_XMMdq_MEMq) = COMISD<V128, MV64>;
DEF_ISEL(VUCOMISD_XMMdq_XMMq) = COMISD<V128, V128>;
DEF_ISEL(VUCOMISS_XMMdq_MEMd) = COMISS<V128, MV32>;
DEF_ISEL(VUCOMISS_XMMdq_XMMd) = COMISS<V128, V128>;
#endif  // HAS_FEATURE_AVX


/*

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

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(SHUFPS, D dst, S1 src1, S2 src2, I8 src3) {
  auto dst_vec = UClearV32(UReadV32(src1));
  auto src1_vec = UReadV32(src1);
  auto src2_vec = UReadV32(src2);
  auto imm = Read(src3);
  auto num_groups = NumVectorElems(dst_vec);

  _Pragma("unroll") for (std::size_t i = 0; i < num_groups; ++i) {
    auto order = UShr8(imm, TruncTo<uint8_t>(i * 2));
    auto sel = UAnd8(order, 0x3_u8);
    auto sel_val = UExtractV32(Select(i < 2, src1_vec, src2_vec), sel);
    dst_vec.elems[i] = sel_val;
  }
  UWriteV32(dst, dst_vec);

  return memory;
}

}  // namespace

DEF_ISEL(SHUFPS_XMMps_XMMps_IMMb) = SHUFPS<V128W, V128, V128>;
DEF_ISEL(SHUFPS_XMMps_MEMps_IMMb) = SHUFPS<V128W, V128, MV128>;


namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(SHUFPD, D dst, S1 src1, S2 src2, I8 src3) {
  auto dst_vec = UClearV64(UReadV64(src1));
  auto src1_vec = UReadV64(src1);
  auto src2_vec = UReadV64(src2);
  auto imm = Read(src3);
  auto num_groups = NumVectorElems(src1_vec);

  _Pragma("unroll") for (std::size_t i = 0; i < num_groups; i += 2) {
    auto order = UShr8(imm, TruncTo<uint8_t>(i));
    auto sel1 = UAnd8(order, 0x1_u8);
    auto sel2 = Select(UAnd8(order, 0x2_u8) == 0x2_u8, 1_u8, 0_u8);
    dst_vec.elems[i] = UExtractV64(src1_vec, i + sel1);
    dst_vec.elems[i + 1] = UExtractV64(src2_vec, i + sel2);
  }

  UWriteV64(dst, dst_vec);

  return memory;
}

}  // namespace

DEF_ISEL(SHUFPD_XMMpd_XMMpd_IMMb) = SHUFPD<V128W, V128, V128>;


namespace {

template <typename D, typename S1>
DEF_SEM(PSHUFD, D dst, S1 src1, I8 src2) {
  auto dst_vec = UClearV32(UReadV32(src1));
  auto src_vec = UReadV128(src1);
  auto num_groups = NumVectorElems(src_vec);

  _Pragma("unroll") for (std::size_t i = 0, k = 0; i < num_groups; ++i) {
    auto group = UExtractV128(src_vec, i);
    auto order = Read(src2);

    _Pragma("unroll") for (std::size_t j = 0; j < 4; ++j, ++k) {
      auto sel = UAnd(order, 0x3_u8);
      auto shift = UMul(sel, 32_u8);
      order = UShr(order, 2_u8);
      auto sel_val = UShr(group, UInt128(shift));
      UUpdateV32(dst_vec, k, TruncTo<uint32_t>(sel_val));
    }
  }
  UWriteV32(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(PSHUFD_XMMdq_MEMdq_IMMb) = PSHUFD<V128W, MV128>;
DEF_ISEL(PSHUFD_XMMdq_XMMdq_IMMb) = PSHUFD<V128W, V128>;
IF_AVX(DEF_ISEL(VPSHUFD_XMMdq_MEMdq_IMMb) = PSHUFD<VV128W, MV128>;)
IF_AVX(DEF_ISEL(VPSHUFD_XMMdq_XMMdq_IMMb) = PSHUFD<VV128W, V128>;)
IF_AVX(DEF_ISEL(VPSHUFD_YMMqq_MEMqq_IMMb) = PSHUFD<VV256W, MV256>;)
IF_AVX(DEF_ISEL(VPSHUFD_YMMqq_YMMqq_IMMb) = PSHUFD<VV256W, V256>;)

/*
4319 VPSHUFD VPSHUFD_ZMMu32_MASKmskw_ZMMu32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
4320 VPSHUFD VPSHUFD_ZMMu32_MASKmskw_MEMu32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX
4321 VPSHUFD VPSHUFD_XMMu32_MASKmskw_XMMu32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
4322 VPSHUFD VPSHUFD_XMMu32_MASKmskw_MEMu32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX
4323 VPSHUFD VPSHUFD_YMMu32_MASKmskw_YMMu32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
4324 VPSHUFD VPSHUFD_YMMu32_MASKmskw_MEMu32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX
 */

namespace {

template <typename D, typename S1>
DEF_SEM(PSHUFLW, D dst, S1 src1, I8 src2) {

  // Source operand is packed with word (16-bit) integers to be shuffled,
  // but src1 is also a vector of one or more 128-bit "lanes":
  auto src_vec = UReadV128(src1);
  auto src_words_vec = UReadV16(src1);

  // Dest operand is similar. DEST[MAXVL-1:128] will be unmodified:
  auto dst_vec = UClearV16(UReadV16(dst));

  // The same operation is done for each 128-bit "lane" of src1:
  auto num_lanes = NumVectorElems(UReadV128(src1));

  _Pragma("unroll") for (std::size_t lane_index = 0, word_index = 0;
                         lane_index < num_lanes; ++lane_index) {
    auto lane = UExtractV128(src_vec, lane_index);

    // Words will be shuffled in the order specified in a code in src2:
    auto order = Read(src2);

    // Shuffle the 4 words from the low 64-bits of the 128-bit lane:
    _Pragma("unroll") for (std::size_t word_count = 0; word_count < 4;
                           ++word_count, ++word_index) {
      auto sel = UAnd(order, 0x3_u8);
      auto shift = UMul(sel, 16_u8);
      order = UShr(order, 2_u8);
      auto sel_val = UShr(lane, UInt128(shift));
      dst_vec = UInsertV16(dst_vec, word_index, TruncTo<uint16_t>(sel_val));
    }

    // After shuffling the low 64-bits, the high 64-bits of the src1 lane is
    // copied to the high quadword of the corresponding destination lane:
    _Pragma("unroll") for (std::size_t word_count = 0; word_count < 4;
                           ++word_count, ++word_index) {
      dst_vec = UInsertV16(dst_vec, word_index,
                           UExtractV16(src_words_vec, word_index));
    }
  }

  UWriteV16(dst, dst_vec);
  return memory;
}

template <typename D, typename S1>
DEF_SEM(PSHUFHW, D dst, S1 src1, I8 src2) {
  auto dst_vec = UReadV16(src1);
  auto src_vec = UReadV16(src1);
  auto imm = Read(src2);
  auto num_groups = NumVectorElems(src_vec);

  _Pragma("unroll") for (std::size_t i = 4; i < num_groups; ++i) {
    auto order = UShr8(imm, TruncTo<uint8_t>((i - 4) * 2_u8));
    auto sel = UAnd8(order, 0x3_u8);
    auto sel_val = UExtractV16(src_vec, sel + 4);
    dst_vec.elems[i] = sel_val;
  }
  UWriteV16(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(PSHUFLW_XMMdq_MEMdq_IMMb) = PSHUFLW<V128W, MV128>;
DEF_ISEL(PSHUFLW_XMMdq_XMMdq_IMMb) = PSHUFLW<V128W, V128>;
IF_AVX(DEF_ISEL(VPSHUFLW_XMMdq_MEMdq_IMMb) = PSHUFLW<VV128W, MV128>;)
IF_AVX(DEF_ISEL(VPSHUFLW_XMMdq_XMMdq_IMMb) = PSHUFLW<VV128W, V128>;)
IF_AVX(DEF_ISEL(VPSHUFLW_YMMqq_MEMqq_IMMb) = PSHUFLW<VV256W, MV256>;)
IF_AVX(DEF_ISEL(VPSHUFLW_YMMqq_YMMqq_IMMb) = PSHUFLW<VV256W, V256>;)

/*
4432 VPSHUFLW VPSHUFLW_XMMu16_MASKmskw_XMMu16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: MASKOP_EVEX
4433 VPSHUFLW VPSHUFLW_XMMu16_MASKmskw_MEMu16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX
4434 VPSHUFLW VPSHUFLW_YMMu16_MASKmskw_YMMu16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: MASKOP_EVEX
4435 VPSHUFLW VPSHUFLW_YMMu16_MASKmskw_MEMu16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX
4436 VPSHUFLW VPSHUFLW_ZMMu16_MASKmskw_ZMMu16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: MASKOP_EVEX
4437 VPSHUFLW VPSHUFLW_ZMMu16_MASKmskw_MEMu16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX
*/

DEF_ISEL(PSHUFHW_XMMdq_XMMdq_IMMb) = PSHUFHW<V128W, V128>;

namespace {

#define MAKE_PCMP(suffix, size, op) \
  template <typename D, typename S1, typename S2> \
  DEF_SEM(PCMP##suffix, D dst, S1 src1, S2 src2) { \
    auto src1_vec = SReadV##size(src1); \
    auto src2_vec = SReadV##size(src2); \
    auto dst_vec = SClearV##size(SReadV##size(dst)); \
    auto num_elems = NumVectorElems(src1_vec); \
    _Pragma("unroll") for (std::size_t i = 0; i < num_elems; ++i) { \
      auto src1_elem = SExtractV##size(src1_vec, i); \
      auto src2_elem = SExtractV##size(src2_vec, i); \
      auto res = Select<int##size##_t>(op(src1_elem, src2_elem), -1_s##size, \
                                       0_s##size); \
      dst_vec = SInsertV##size(dst_vec, i, res); \
    } \
    SWriteV##size(dst, dst_vec); \
    return memory; \
  }

MAKE_PCMP(GTQ, 64, SCmpGt)
MAKE_PCMP(GTW, 16, SCmpGt)
MAKE_PCMP(GTB, 8, SCmpGt)
MAKE_PCMP(GTD, 32, SCmpGt)

MAKE_PCMP(EQQ, 64, SCmpEq)
MAKE_PCMP(EQW, 16, SCmpEq)
MAKE_PCMP(EQB, 8, SCmpEq)
MAKE_PCMP(EQD, 32, SCmpEq)
}  // namespace

DEF_ISEL(PCMPGTB_MMXq_MMXq) = PCMPGTB<V64W, V64, V64>;
DEF_ISEL(PCMPGTB_MMXq_MEMq) = PCMPGTB<V64W, V64, MV64>;
DEF_ISEL(PCMPGTW_MMXq_MMXq) = PCMPGTW<V64W, V64, V64>;
DEF_ISEL(PCMPGTW_MMXq_MEMq) = PCMPGTW<V64W, V64, MV64>;
DEF_ISEL(PCMPGTD_MMXq_MMXq) = PCMPGTD<V64W, V64, V64>;
DEF_ISEL(PCMPGTD_MMXq_MEMq) = PCMPGTD<V64W, V64, MV64>;

DEF_ISEL(PCMPGTQ_XMMdq_MEMdq) = PCMPGTQ<V128W, V128, MV128>;
DEF_ISEL(PCMPGTQ_XMMdq_XMMdq) = PCMPGTQ<V128W, V128, V128>;
DEF_ISEL(PCMPGTW_XMMdq_MEMdq) = PCMPGTW<V128W, V128, MV128>;
DEF_ISEL(PCMPGTW_XMMdq_XMMdq) = PCMPGTW<V128W, V128, V128>;
DEF_ISEL(PCMPGTB_XMMdq_MEMdq) = PCMPGTB<V128W, V128, MV128>;
DEF_ISEL(PCMPGTB_XMMdq_XMMdq) = PCMPGTB<V128W, V128, V128>;
DEF_ISEL(PCMPGTD_XMMdq_MEMdq) = PCMPGTD<V128W, V128, MV128>;
DEF_ISEL(PCMPGTD_XMMdq_XMMdq) = PCMPGTD<V128W, V128, V128>;

#if HAS_FEATURE_AVX
DEF_ISEL(VPCMPGTQ_XMMdq_XMMdq_MEMdq) = PCMPGTQ<VV128W, V128, MV128>;
DEF_ISEL(VPCMPGTQ_XMMdq_XMMdq_XMMdq) = PCMPGTQ<VV128W, V128, V128>;
DEF_ISEL(VPCMPGTQ_YMMqq_YMMqq_MEMqq) = PCMPGTQ<VV256W, V256, MV256>;
DEF_ISEL(VPCMPGTQ_YMMqq_YMMqq_YMMqq) = PCMPGTQ<VV256W, V256, V256>;
DEF_ISEL(VPCMPGTW_XMMdq_XMMdq_MEMdq) = PCMPGTW<VV128W, V128, MV128>;
DEF_ISEL(VPCMPGTW_XMMdq_XMMdq_XMMdq) = PCMPGTW<VV128W, V128, V128>;
DEF_ISEL(VPCMPGTW_YMMqq_YMMqq_MEMqq) = PCMPGTW<VV256W, V256, MV256>;
DEF_ISEL(VPCMPGTW_YMMqq_YMMqq_YMMqq) = PCMPGTW<VV256W, V256, V256>;
DEF_ISEL(VPCMPGTB_XMMdq_XMMdq_MEMdq) = PCMPGTB<VV128W, V128, MV128>;
DEF_ISEL(VPCMPGTB_XMMdq_XMMdq_XMMdq) = PCMPGTB<VV128W, V128, V128>;
DEF_ISEL(VPCMPGTB_YMMqq_YMMqq_MEMqq) = PCMPGTB<VV256W, V256, MV256>;
DEF_ISEL(VPCMPGTB_YMMqq_YMMqq_YMMqq) = PCMPGTB<VV256W, V256, V256>;
DEF_ISEL(VPCMPGTD_XMMdq_XMMdq_MEMdq) = PCMPGTD<VV128W, V128, MV128>;
DEF_ISEL(VPCMPGTD_XMMdq_XMMdq_XMMdq) = PCMPGTD<VV128W, V128, V128>;
DEF_ISEL(VPCMPGTD_YMMqq_YMMqq_MEMqq) = PCMPGTD<VV256W, V256, MV256>;
DEF_ISEL(VPCMPGTD_YMMqq_YMMqq_YMMqq) = PCMPGTD<VV256W, V256, V256>;
#endif  // HAS_FEATURE_AVX

DEF_ISEL(PCMPEQB_MMXq_MMXq) = PCMPEQB<V64W, V64, V64>;
DEF_ISEL(PCMPEQB_MMXq_MEMq) = PCMPEQB<V64W, V64, MV64>;
DEF_ISEL(PCMPEQW_MMXq_MMXq) = PCMPEQW<V64W, V64, V64>;
DEF_ISEL(PCMPEQW_MMXq_MEMq) = PCMPEQW<V64W, V64, MV64>;
DEF_ISEL(PCMPEQD_MMXq_MMXq) = PCMPEQD<V64W, V64, V64>;
DEF_ISEL(PCMPEQD_MMXq_MEMq) = PCMPEQD<V64W, V64, MV64>;

DEF_ISEL(PCMPEQQ_XMMdq_MEMdq) = PCMPEQQ<V128W, V128, MV128>;
DEF_ISEL(PCMPEQQ_XMMdq_XMMdq) = PCMPEQQ<V128W, V128, V128>;
DEF_ISEL(PCMPEQW_XMMdq_MEMdq) = PCMPEQW<V128W, V128, MV128>;
DEF_ISEL(PCMPEQW_XMMdq_XMMdq) = PCMPEQW<V128W, V128, V128>;
DEF_ISEL(PCMPEQB_XMMdq_MEMdq) = PCMPEQB<V128W, V128, MV128>;
DEF_ISEL(PCMPEQB_XMMdq_XMMdq) = PCMPEQB<V128W, V128, V128>;
DEF_ISEL(PCMPEQD_XMMdq_MEMdq) = PCMPEQD<V128W, V128, MV128>;
DEF_ISEL(PCMPEQD_XMMdq_XMMdq) = PCMPEQD<V128W, V128, V128>;

#if HAS_FEATURE_AVX
DEF_ISEL(VPCMPEQQ_XMMdq_XMMdq_MEMdq) = PCMPEQQ<VV128W, V128, MV128>;
DEF_ISEL(VPCMPEQQ_XMMdq_XMMdq_XMMdq) = PCMPEQQ<VV128W, V128, V128>;
DEF_ISEL(VPCMPEQQ_YMMqq_YMMqq_MEMqq) = PCMPEQQ<VV256W, V256, MV256>;
DEF_ISEL(VPCMPEQQ_YMMqq_YMMqq_YMMqq) = PCMPEQQ<VV256W, V256, V256>;
DEF_ISEL(VPCMPEQW_XMMdq_XMMdq_MEMdq) = PCMPEQW<VV128W, V128, MV128>;
DEF_ISEL(VPCMPEQW_XMMdq_XMMdq_XMMdq) = PCMPEQW<VV128W, V128, V128>;
DEF_ISEL(VPCMPEQW_YMMqq_YMMqq_MEMqq) = PCMPEQW<VV256W, V256, MV256>;
DEF_ISEL(VPCMPEQW_YMMqq_YMMqq_YMMqq) = PCMPEQW<VV256W, V256, V256>;
DEF_ISEL(VPCMPEQB_XMMdq_XMMdq_MEMdq) = PCMPEQB<VV128W, V128, MV128>;
DEF_ISEL(VPCMPEQB_XMMdq_XMMdq_XMMdq) = PCMPEQB<VV128W, V128, V128>;
DEF_ISEL(VPCMPEQB_YMMqq_YMMqq_MEMqq) = PCMPEQB<VV256W, V256, MV256>;
DEF_ISEL(VPCMPEQB_YMMqq_YMMqq_YMMqq) = PCMPEQB<VV256W, V256, V256>;
DEF_ISEL(VPCMPEQD_XMMdq_XMMdq_MEMdq) = PCMPEQD<VV128W, V128, MV128>;
DEF_ISEL(VPCMPEQD_XMMdq_XMMdq_XMMdq) = PCMPEQD<VV128W, V128, V128>;
DEF_ISEL(VPCMPEQD_YMMqq_YMMqq_MEMqq) = PCMPEQD<VV256W, V256, MV256>;
DEF_ISEL(VPCMPEQD_YMMqq_YMMqq_YMMqq) = PCMPEQD<VV256W, V256, V256>;
#endif  // HAS_FEATURE_AVX

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(CMPSS, D dst, S1 src1, S2 src2, I8 src3) {
  auto src1_vec = FReadV32(src1);
  auto src2_vec = FReadV32(src2);
  auto dst_vec = UClearV32(UReadV32(dst));
  auto op = Read(src3);
  if (op >= 32) {
    StopFailure();
  }
  auto v1 = FExtractV32(src1_vec, 0);
  auto v2 = FExtractV32(src2_vec, 0);
  bool cond =
      CompareFloats<float32_t>(static_cast<FloatCompareOperator>(op), v1, v2);

  dst_vec = UInsertV32(dst_vec, 0, Select<uint32_t>(cond, ~0_u32, 0_u32));

  UWriteV32(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(CMPSD, D dst, S1 src1, S2 src2, I8 src3) {
  auto src1_vec = FReadV64(src1);
  auto src2_vec = FReadV64(src2);
  auto dst_vec = UClearV64(UReadV64(dst));
  auto op = Read(src3);
  if (op >= 32) {
    StopFailure();
  }
  auto v1 = FExtractV64(src1_vec, 0);
  auto v2 = FExtractV64(src2_vec, 0);
  bool cond =
      CompareFloats<float64_t>(static_cast<FloatCompareOperator>(op), v1, v2);

  dst_vec = UInsertV64(dst_vec, 0, Select<uint64_t>(cond, ~0_u64, 0_u64));

  UWriteV64(dst, dst_vec);
  return memory;
}


}  // namespace

DEF_ISEL(CMPSS_XMMss_MEMss_IMMb) = CMPSS<V128W, V128, MV32>;
DEF_ISEL(CMPSS_XMMss_XMMss_IMMb) = CMPSS<V128W, V128, V128>;

#if HAS_FEATURE_AVX
DEF_ISEL(VCMPSS_XMMdq_XMMdq_MEMd_IMMb) = CMPSS<VV128W, V128, MV32>;
DEF_ISEL(VCMPSS_XMMdq_XMMdq_XMMd_IMMb) = CMPSS<VV128W, V128, V128>;
#endif  // HAS_FEATURE_AVX

DEF_ISEL(CMPSD_XMM_XMMsd_MEMsd_IMMb) = CMPSD<V128W, V128, MV64>;
DEF_ISEL(CMPSD_XMM_XMMsd_XMMsd_IMMb) = CMPSD<V128W, V128, V128>;

#if HAS_FEATURE_AVX
DEF_ISEL(VCMPSD_XMMdq_XMMdq_MEMq_IMMb) = CMPSD<VV128W, V128, MV64>;
DEF_ISEL(VCMPSD_XMMdq_XMMdq_XMMq_IMMb) = CMPSD<VV128W, V128, V128>;
#endif  // HAS_FEATURE_AVX

namespace {
template <typename D, typename S1, typename S2>
DEF_SEM(CMPPS, D dst, S1 src1, S2 src2, I8 src3) {
  auto src1_vec = FReadV32(src1);
  auto src2_vec = FReadV32(src2);
  auto dst_vec = UClearV32(UReadV32(dst));
  auto op = Read(src3);
  if (op >= 32) {
    StopFailure();
  }

  auto vec_count = NumVectorElems(src2_vec);
  _Pragma("unroll") for (std::size_t i = 0; i < vec_count; i++) {
    auto v1 = FExtractV32(src1_vec, i);
    auto v2 = FExtractV32(src2_vec, i);

    bool cond =
        CompareFloats<float32_t>(static_cast<FloatCompareOperator>(op), v1, v2);

    auto res = Select<uint32_t>(cond, ~0_u32, 0_u32);
    dst_vec = UInsertV32(dst_vec, i, res);
  }
  UWriteV32(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(CMPPD, D dst, S1 src1, S2 src2, I8 src3) {
  auto src1_vec = FReadV64(src1);
  auto src2_vec = FReadV64(src2);
  auto dst_vec = UClearV64(UReadV64(dst));
  auto op = Read(src3);
  if (op >= 32) {
    StopFailure();
  }

  auto vec_count = NumVectorElems(src2_vec);
  _Pragma("unroll") for (std::size_t i = 0; i < vec_count; i++) {
    auto v1 = FExtractV64(src1_vec, i);
    auto v2 = FExtractV64(src2_vec, i);

    bool cond =
        CompareFloats<float64_t>(static_cast<FloatCompareOperator>(op), v1, v2);

    auto res = Select<uint64_t>(cond, ~0_u64, 0_u64);
    dst_vec = UInsertV64(dst_vec, i, res);
  }
  UWriteV64(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(CMPPS_XMMps_MEMps_IMMb) = CMPPS<V128W, V128, MV128>;
DEF_ISEL(CMPPS_XMMps_XMMps_IMMb) = CMPPS<V128W, V128, V128>;

#if HAS_FEATURE_AVX
DEF_ISEL(VCMPPS_XMMdq_XMMdq_MEMdq_IMMb) = CMPPS<VV128W, V128, MV128>;
DEF_ISEL(VCMPPS_XMMdq_XMMdq_XMMdq_IMMb) = CMPPS<VV128W, V128, V128>;
DEF_ISEL(VCMPPS_YMMqq_YMMqq_MEMqq_IMMb) = CMPPS<VV256W, V256, MV256>;
DEF_ISEL(VCMPPS_YMMqq_YMMqq_YMMqq_IMMb) = CMPPS<VV256W, V256, V256>;
#endif  // HAS_FEATURE_AVX

DEF_ISEL(CMPPD_XMMpd_MEMpd_IMMb) = CMPPD<V128W, V128, MV128>;
DEF_ISEL(CMPPD_XMMpd_XMMpd_IMMb) = CMPPD<V128W, V128, V128>;

#if HAS_FEATURE_AVX
DEF_ISEL(VCMPPD_XMMdq_XMMdq_MEMdq_IMMb) = CMPPD<VV128W, V128, MV128>;
DEF_ISEL(VCMPPD_XMMdq_XMMdq_XMMdq_IMMb) = CMPPD<VV128W, V128, V128>;
DEF_ISEL(VCMPPD_YMMqq_YMMqq_MEMqq_IMMb) = CMPPD<VV256W, V256, MV256>;
DEF_ISEL(VCMPPD_YMMqq_YMMqq_YMMqq_IMMb) = CMPPD<VV256W, V256, V256>;
#endif  // HAS_FEATURE_AVX

namespace {

enum InputFormat : uint8_t { kUInt8 = 0, kUInt16 = 1, kInt8 = 2, kInt16 = 3 };

enum AggregationOperation : uint8_t {
  kEqualAny = 0,
  kRanges = 1,
  kEqualEach = 2,
  kEqualOrdered = 3
};

enum Polarity : uint8_t {
  kPositive = 0,
  kNegative = 1,
  kMaskedPositive = 2,
  kMaskedNegative = 3
};

enum OutputSelection : uint8_t {
  kLeastSignificantIndex = 0,
  kMostSignificantIndex = 1
};

union StringCompareControl {
  uint8_t flat;
  struct {
    uint8_t input_format : 2;
    uint8_t agg_operation : 2;
    uint8_t polarity : 2;
    uint8_t output_selection : 1;
    uint8_t should_be_0 : 1;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(1 == sizeof(StringCompareControl),
              "Invalid packing of `StringCompareControl`.");

template <size_t x, size_t y>
class BitMatrix : std::bitset<x * y> {
 public:
  ALWAYS_INLINE bool Test(size_t i, size_t j) const {
    return this->operator[]((x * i) + j);
  }

  ALWAYS_INLINE void Set(size_t i, size_t j, bool val) {
    this->operator[]((x * i) + j) = val;
  }

 private:
  bool rows[x][y];
};

// src1 is a char set, src2 is a string. We set a bit of `int_res_1` to `1`
// when a char in `src2` belongs to the char set `src1`.
template <size_t num_elems>
ALWAYS_INLINE static uint16_t
AggregateEqualAny(const BitMatrix<num_elems, num_elems> &bool_res,
                  const size_t src1_len, const size_t src2_len) {

  uint16_t int_res_1 = 0;
  uint16_t bit = 1;
  for (size_t j = 0; j < src2_len; ++j, bit <<= 1) {

    _Pragma("unroll") for (size_t i = 0; i < src1_len; ++i) {
      if (bool_res.Test(i, j)) {
        int_res_1 |= bit;
        break;  // src2_j is in src1, at position src1_i.
      }
    }
  }
  return int_res_1;
}

// `src2` is a string, and `src1` is kind of like a the ranges of regular
// expression character classes.
template <size_t num_elems>
ALWAYS_INLINE static uint16_t
AggregateRanges(const BitMatrix<num_elems, num_elems> &bool_res,
                const size_t src1_len, const size_t src2_len) {

  uint16_t int_res_1 = 0;
  uint16_t bit = 1;

  for (size_t j = 0; j < src2_len; ++j, bit <<= 1) {

    _Pragma("unroll") for (size_t i = 0; i < (src1_len - 1); i += 2) {
      const auto geq_lower_bound = bool_res.Test(i, j);
      const auto leq_upper_bound = bool_res.Test(i + 1, j);
      if (geq_lower_bound && leq_upper_bound) {
        int_res_1 |= bit;  // src2_j is in the range [src1_i, src1_i+1]
        break;
      }
    }
  }
  return int_res_1;
}

template <size_t num_elems>
ALWAYS_INLINE static uint16_t
AggregateEqualEach(const BitMatrix<num_elems, num_elems> &bool_res,
                   const size_t src1_len, const size_t src2_len) {

  uint16_t int_res_1 = 0;
  uint16_t bit = 1;

  _Pragma("unroll") for (size_t i = 0; i < num_elems; ++i, bit <<= 1) {
    const bool in_str1 = i < src1_len;
    const bool in_str2 = i < src2_len;
    if (in_str1 && in_str2) {
      if (bool_res.Test(i, i)) {
        int_res_1 |= bit;
      }
    } else if (!in_str1 && !in_str2) {
      int_res_1 |= bit;
    }
  }
  return int_res_1;
}

// This is really `strstr`, i.e. searching for `src1` in `src2`.
template <size_t num_elems>
ALWAYS_INLINE static uint16_t
AggregateEqualOrdered(const BitMatrix<num_elems, num_elems> &bool_res,
                      const size_t src1_len, const size_t src2_len) {

  if (src1_len > src2_len) {
    return 0;
  }

  uint16_t int_res_1 = (0xFFFF_u16 >> (16 - num_elems));
  uint16_t bit = 1;

  for (size_t j = 0; j < num_elems; ++j, bit <<= 1) {

    _Pragma("unroll") for (size_t i = 0, k = j;
                           i < (num_elems - j) && k < num_elems; ++i, ++k) {
      auto needle_valid = i < src1_len;
      auto haystack_valid = k < src2_len;

      if (!needle_valid) {
        break;
      } else if (!haystack_valid || !bool_res.Test(i, k)) {
        int_res_1 ^= bit;
        break;
      }
    }
  }

  return int_res_1;
}

template <typename V, size_t num_elems>
DEF_SEM(DoPCMPISTRI, const V &src1, const V &src2,
        StringCompareControl control) {
  BitMatrix<num_elems, num_elems> bool_res;
  size_t src1_len = num_elems;
  size_t src2_len = num_elems;

  const auto agg_operation =
      static_cast<AggregationOperation>(control.agg_operation);

  const auto polarity = static_cast<Polarity>(control.polarity);
  const auto output_selection =
      static_cast<OutputSelection>(control.output_selection);

  _Pragma("unroll") for (size_t i = 0; i < num_elems; ++i) {
    if (!src1.elems[i]) {
      src1_len = std::min<size_t>(src1_len, i);
    }
    if (!src2.elems[i]) {
      src2_len = std::min<size_t>(src2_len, i);
    }
  }

  for (size_t n = 0; n < num_elems; ++n) {
    const auto reg = src1.elems[n];

    _Pragma("unroll") for (size_t m = 0; m < num_elems; ++m) {
      const auto reg_mem = src2.elems[m];

      switch (agg_operation) {
        case kEqualAny:
        case kEqualEach:
        case kEqualOrdered: bool_res.Set(n, m, reg == reg_mem); break;

        // Checking is `src2[m]` is in the range of `src1[n]` and `src1[n+1]`.
        case kRanges:
          if (n & 1U) {  // Odd.
            bool_res.Set(n, m, reg_mem <= reg);  // `z` and `Z` in `azAZ`.
          } else {  // Even.
            bool_res.Set(n, m, reg_mem >= reg);  // `a` and `A` in `azAZ`.
          }
          break;
      }
    }
  }

  uint16_t int_res_1 = 0;

  switch (agg_operation) {
    case kEqualAny:
      int_res_1 = AggregateEqualAny<num_elems>(bool_res, src1_len, src2_len);
      break;
    case kRanges:
      int_res_1 = AggregateRanges<num_elems>(bool_res, src1_len, src2_len);
      break;
    case kEqualEach:
      int_res_1 = AggregateEqualEach<num_elems>(bool_res, src1_len, src2_len);
      break;
    case kEqualOrdered:
      int_res_1 =
          AggregateEqualOrdered<num_elems>(bool_res, src1_len, src2_len);
      break;
  }

  uint16_t int_res_2 = 0;
  switch (polarity) {
    case kPositive: int_res_2 = int_res_1; break;
    case kNegative:
      int_res_2 = (0xFFFF_u16 >> (16 - num_elems)) ^ int_res_1;
      break;
    case kMaskedPositive: int_res_2 = int_res_1; break;
    case kMaskedNegative:
      int_res_2 = int_res_1;
      _Pragma("unroll") for (size_t i = 0; i < num_elems; ++i) {
        auto mask = static_cast<uint16_t>(1_u16 << i);
        if (i < src2_len) {
          int_res_2 ^= mask;
        }
      }
      break;
  }

  uint16_t index = num_elems;
  switch (output_selection) {
    case kLeastSignificantIndex:
      if (auto lsb_index = __builtin_ffs(int_res_2)) {
        index = static_cast<uint16_t>(lsb_index - 1);
      }
      break;
    case kMostSignificantIndex:
      if (int_res_2) {
        uint16_t count = CountLeadingZeros(int_res_2) - (16_u16 - num_elems);
        index = num_elems - count - 1;
      }
      break;
  }

  Write(REG_XCX, static_cast<addr_t>(index));
  Write(FLAG_CF, int_res_2 != 0_u16);
  Write(FLAG_ZF, src2_len < num_elems);
  Write(FLAG_SF, src1_len < num_elems);
  Write(FLAG_OF, 0_u16 != (int_res_2 & 1_u16));
  Write(FLAG_AF, false);
  Write(FLAG_PF, false);
  return memory;
}

template <typename S2>
DEF_SEM(PCMPISTRI, V128 src1, S2 src2, I8 src3) {
  const StringCompareControl control = {.flat = Read(src3)};
  switch (static_cast<InputFormat>(control.input_format)) {
    case kUInt8:
      return DoPCMPISTRI<uint8v16_t, 16>(memory, state, UReadV8(src1),
                                         UReadV8(src2), control);
    case kUInt16:
      return DoPCMPISTRI<uint16v8_t, 8>(memory, state, UReadV16(src1),
                                        UReadV16(src2), control);
    case kInt8:
      return DoPCMPISTRI<int8v16_t, 16>(memory, state, SReadV8(src1),
                                        SReadV8(src2), control);
    case kInt16:
      return DoPCMPISTRI<int16v8_t, 8>(memory, state, SReadV16(src1),
                                       SReadV16(src2), control);
  }
  return memory;
}

}  // namespace

DEF_ISEL(PCMPISTRI_XMMdq_XMMdq_IMMb) = PCMPISTRI<V128>;
DEF_ISEL(PCMPISTRI_XMMdq_MEMdq_IMMb) = PCMPISTRI<MV128>;
IF_AVX(DEF_ISEL(VPCMPISTRI_XMMdq_XMMdq_IMMb) = PCMPISTRI<V128>;)
IF_AVX(DEF_ISEL(VPCMPISTRI_XMMdq_MEMdq_IMMb) = PCMPISTRI<MV128>;)

namespace {

template <typename D, typename S>
DEF_SEM(PSRLDQ, D dst, S src1, I8 src2) {
  auto vec = UReadV8(src1);
  auto new_vec = UClearV8(UReadV8(dst));
  auto shift = std::min<size_t>(Read(src2), 16);
  _Pragma("unroll") for (size_t i = shift, j = 0; i < 16; ++i, ++j) {
    new_vec = UInsertV8(new_vec, j, UExtractV8(vec, i));
  }
  UWriteV8(dst, new_vec);
  return memory;
}

#if HAS_FEATURE_AVX

template <typename D, typename S>
DEF_SEM(VPSRLDQ, D dst, S src1, I8 src2) {
  auto vec = UReadV8(src1);
  auto new_vec = UClearV8(UReadV8(dst));
  auto shift = std::min<size_t>(Read(src2), 16);
  _Pragma("unroll") for (size_t i = shift, j = 0; i < 16; ++i, ++j) {
    new_vec = UInsertV8(new_vec, j, UExtractV8(vec, i));
    new_vec = UInsertV8(new_vec, j + 16, UExtractV8(vec, i + 16));
  }
  UWriteV8(dst, new_vec);
  return memory;
}

#endif  // HAS_FEATURE_AVX

}  // namespace

DEF_ISEL(PSRLDQ_XMMdq_IMMb) = PSRLDQ<V128W, V128>;
IF_AVX(DEF_ISEL(VPSRLDQ_XMMdq_XMMdq_IMMb) = PSRLDQ<VV128W, V128>;)
IF_AVX(DEF_ISEL(VPSRLDQ_YMMqq_YMMqq_IMMb) = VPSRLDQ<VV256W, V256>;)

/*

1291 PSRLQ PSRLQ_MMXq_IMMb MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
1292 PSRLQ PSRLQ_XMMdq_IMMb SSE SSE2 SSE2 ATTRIBUTES:
1293 PSRLQ PSRLQ_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
1294 PSRLQ PSRLQ_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
1295 PSRLQ PSRLQ_XMMdq_MEMdq SSE SSE2 SSE2 ATTRIBUTES: REQUIRES_ALIGNMENT SIMD_PACKED_ALIGNMENT
1296 PSRLQ PSRLQ_XMMdq_XMMdq SSE SSE2 SSE2 ATTRIBUTES: REQUIRES_ALIGNMENT SIMD_PACKED_ALIGNMENT
1297 PSRLW PSRLW_MMXq_IMMb MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
1298 PSRLW PSRLW_XMMdq_IMMb SSE SSE2 SSE2 ATTRIBUTES:
1299 PSRLW PSRLW_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
1300 PSRLW PSRLW_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
1301 PSRLW PSRLW_XMMdq_MEMdq SSE SSE2 SSE2 ATTRIBUTES: REQUIRES_ALIGNMENT SIMD_PACKED_ALIGNMENT
1302 PSRLW PSRLW_XMMdq_XMMdq SSE SSE2 SSE2 ATTRIBUTES: REQUIRES_ALIGNMENT SIMD_PACKED_ALIGNMENT
1310 PSRLD PSRLD_MMXq_IMMb MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
1311 PSRLD PSRLD_XMMdq_IMMb SSE SSE2 SSE2 ATTRIBUTES:
1312 PSRLD PSRLD_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
1313 PSRLD PSRLD_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
1314 PSRLD PSRLD_XMMdq_MEMdq SSE SSE2 SSE2 ATTRIBUTES: REQUIRES_ALIGNMENT SIMD_PACKED_ALIGNMENT
1315 PSRLD PSRLD_XMMdq_XMMdq SSE SSE2 SSE2 ATTRIBUTES: REQUIRES_ALIGNMENT SIMD_PACKED_ALIGNMENT
2266 VPSRLVQ VPSRLVQ_XMMdq_XMMdq_MEMdq AVX2 AVX2 AVX2 ATTRIBUTES:
2267 VPSRLVQ VPSRLVQ_XMMdq_XMMdq_XMMdq AVX2 AVX2 AVX2 ATTRIBUTES:
2268 VPSRLVQ VPSRLVQ_YMMqq_YMMqq_MEMqq AVX2 AVX2 AVX2 ATTRIBUTES:
2269 VPSRLVQ VPSRLVQ_YMMqq_YMMqq_YMMqq AVX2 AVX2 AVX2 ATTRIBUTES:
2289 VPSRLVD VPSRLVD_XMMdq_XMMdq_MEMdq AVX2 AVX2 AVX2 ATTRIBUTES:
2290 VPSRLVD VPSRLVD_XMMdq_XMMdq_XMMdq AVX2 AVX2 AVX2 ATTRIBUTES:
2291 VPSRLVD VPSRLVD_YMMqq_YMMqq_MEMqq AVX2 AVX2 AVX2 ATTRIBUTES:
2292 VPSRLVD VPSRLVD_YMMqq_YMMqq_YMMqq AVX2 AVX2 AVX2 ATTRIBUTES:
3161 VPSRLW VPSRLW_XMMdq_XMMdq_MEMdq AVX AVX AVX ATTRIBUTES:
3162 VPSRLW VPSRLW_XMMdq_XMMdq_XMMdq AVX AVX AVX ATTRIBUTES:
3163 VPSRLW VPSRLW_XMMdq_XMMdq_IMMb AVX AVX AVX ATTRIBUTES:
3164 VPSRLW VPSRLW_YMMqq_YMMqq_MEMdq AVX2 AVX2 AVX2 ATTRIBUTES:
3165 VPSRLW VPSRLW_YMMqq_YMMqq_XMMq AVX2 AVX2 AVX2 ATTRIBUTES:
3166 VPSRLW VPSRLW_YMMqq_YMMqq_IMMb AVX2 AVX2 AVX2 ATTRIBUTES:
3167 VPSRLQ VPSRLQ_XMMdq_XMMdq_MEMdq AVX AVX AVX ATTRIBUTES:
3168 VPSRLQ VPSRLQ_XMMdq_XMMdq_XMMdq AVX AVX AVX ATTRIBUTES:
3169 VPSRLQ VPSRLQ_XMMdq_XMMdq_IMMb AVX AVX AVX ATTRIBUTES:
3170 VPSRLQ VPSRLQ_YMMqq_YMMqq_MEMdq AVX2 AVX2 AVX2 ATTRIBUTES:
3171 VPSRLQ VPSRLQ_YMMqq_YMMqq_XMMq AVX2 AVX2 AVX2 ATTRIBUTES:
3172 VPSRLQ VPSRLQ_YMMqq_YMMqq_IMMb AVX2 AVX2 AVX2 ATTRIBUTES:
3195 VPSRLD VPSRLD_XMMdq_XMMdq_MEMdq AVX AVX AVX ATTRIBUTES:
3196 VPSRLD VPSRLD_XMMdq_XMMdq_XMMdq AVX AVX AVX ATTRIBUTES:
3197 VPSRLD VPSRLD_XMMdq_XMMdq_IMMb AVX AVX AVX ATTRIBUTES:
3198 VPSRLD VPSRLD_YMMqq_YMMqq_MEMdq AVX2 AVX2 AVX2 ATTRIBUTES:
3199 VPSRLD VPSRLD_YMMqq_YMMqq_XMMq AVX2 AVX2 AVX2 ATTRIBUTES:
3200 VPSRLD VPSRLD_YMMqq_YMMqq_IMMb AVX2 AVX2 AVX2 ATTRIBUTES:
3992 VPSRLVQ VPSRLVQ_ZMMu64_MASKmskw_ZMMu64_ZMMu64_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
3993 VPSRLVQ VPSRLVQ_ZMMu64_MASKmskw_ZMMu64_MEMu64_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
3994 VPSRLVQ VPSRLVQ_XMMu64_MASKmskw_XMMu64_XMMu64_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
3995 VPSRLVQ VPSRLVQ_XMMu64_MASKmskw_XMMu64_MEMu64_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
3996 VPSRLVQ VPSRLVQ_YMMu64_MASKmskw_YMMu64_YMMu64_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
3997 VPSRLVQ VPSRLVQ_YMMu64_MASKmskw_YMMu64_MEMu64_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
4004 VPSRLVW VPSRLVW_XMMu16_MASKmskw_XMMu16_XMMu16_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: MASKOP_EVEX
4005 VPSRLVW VPSRLVW_XMMu16_MASKmskw_XMMu16_MEMu16_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
4006 VPSRLVW VPSRLVW_YMMu16_MASKmskw_YMMu16_YMMu16_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: MASKOP_EVEX
4007 VPSRLVW VPSRLVW_YMMu16_MASKmskw_YMMu16_MEMu16_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
4008 VPSRLVW VPSRLVW_ZMMu16_MASKmskw_ZMMu16_ZMMu16_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: MASKOP_EVEX
4009 VPSRLVW VPSRLVW_ZMMu16_MASKmskw_ZMMu16_MEMu16_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
4063 VPSRLVD VPSRLVD_ZMMu32_MASKmskw_ZMMu32_ZMMu32_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
4064 VPSRLVD VPSRLVD_ZMMu32_MASKmskw_ZMMu32_MEMu32_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
4065 VPSRLVD VPSRLVD_XMMu32_MASKmskw_XMMu32_XMMu32_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
4066 VPSRLVD VPSRLVD_XMMu32_MASKmskw_XMMu32_MEMu32_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
4067 VPSRLVD VPSRLVD_YMMu32_MASKmskw_YMMu32_YMMu32_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
4068 VPSRLVD VPSRLVD_YMMu32_MASKmskw_YMMu32_MEMu32_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
4093 VPSRLDQ VPSRLDQ_XMMu8_XMMu8_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES:
4094 VPSRLDQ VPSRLDQ_XMMu8_MEMu8_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: DISP8_FULLMEM
4095 VPSRLDQ VPSRLDQ_YMMu8_YMMu8_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES:
4096 VPSRLDQ VPSRLDQ_YMMu8_MEMu8_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: DISP8_FULLMEM
4097 VPSRLDQ VPSRLDQ_ZMMu8_ZMMu8_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES:
4098 VPSRLDQ VPSRLDQ_ZMMu8_MEMu8_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: DISP8_FULLMEM
5561 VPSRLW VPSRLW_XMMu16_MASKmskw_XMMu16_XMMu16_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: MASKOP_EVEX
5562 VPSRLW VPSRLW_XMMu16_MASKmskw_XMMu16_MEMu16_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: DISP8_MEM128 MASKOP_EVEX
5563 VPSRLW VPSRLW_XMMu16_MASKmskw_XMMu16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: MASKOP_EVEX
5564 VPSRLW VPSRLW_XMMu16_MASKmskw_MEMu16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5565 VPSRLW VPSRLW_YMMu16_MASKmskw_YMMu16_XMMu16_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: MASKOP_EVEX
5566 VPSRLW VPSRLW_YMMu16_MASKmskw_YMMu16_MEMu16_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: DISP8_MEM128 MASKOP_EVEX
5567 VPSRLW VPSRLW_YMMu16_MASKmskw_YMMu16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: MASKOP_EVEX
5568 VPSRLW VPSRLW_YMMu16_MASKmskw_MEMu16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5569 VPSRLW VPSRLW_ZMMu16_MASKmskw_ZMMu16_XMMu16_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: MASKOP_EVEX
5570 VPSRLW VPSRLW_ZMMu16_MASKmskw_ZMMu16_MEMu16_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: DISP8_MEM128 MASKOP_EVEX
5571 VPSRLW VPSRLW_ZMMu16_MASKmskw_ZMMu16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: MASKOP_EVEX
5572 VPSRLW VPSRLW_ZMMu16_MASKmskw_MEMu16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5573 VPSRLQ VPSRLQ_ZMMu64_MASKmskw_ZMMu64_XMMu64_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
5574 VPSRLQ VPSRLQ_ZMMu64_MASKmskw_ZMMu64_MEMu64_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: DISP8_MEM128 MASKOP_EVEX
5575 VPSRLQ VPSRLQ_ZMMu64_MASKmskw_ZMMu64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
5576 VPSRLQ VPSRLQ_ZMMu64_MASKmskw_MEMu64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5577 VPSRLQ VPSRLQ_XMMu64_MASKmskw_XMMu64_XMMu64_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
5578 VPSRLQ VPSRLQ_XMMu64_MASKmskw_XMMu64_MEMu64_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: DISP8_MEM128 MASKOP_EVEX
5579 VPSRLQ VPSRLQ_XMMu64_MASKmskw_XMMu64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
5580 VPSRLQ VPSRLQ_XMMu64_MASKmskw_MEMu64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5581 VPSRLQ VPSRLQ_YMMu64_MASKmskw_YMMu64_XMMu64_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
5582 VPSRLQ VPSRLQ_YMMu64_MASKmskw_YMMu64_MEMu64_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: DISP8_MEM128 MASKOP_EVEX
5583 VPSRLQ VPSRLQ_YMMu64_MASKmskw_YMMu64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
5584 VPSRLQ VPSRLQ_YMMu64_MASKmskw_MEMu64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5615 VPSRLD VPSRLD_ZMMu32_MASKmskw_ZMMu32_XMMu32_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
5616 VPSRLD VPSRLD_ZMMu32_MASKmskw_ZMMu32_MEMu32_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: DISP8_MEM128 MASKOP_EVEX
5617 VPSRLD VPSRLD_ZMMu32_MASKmskw_ZMMu32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
5618 VPSRLD VPSRLD_ZMMu32_MASKmskw_MEMu32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5619 VPSRLD VPSRLD_XMMu32_MASKmskw_XMMu32_XMMu32_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
5620 VPSRLD VPSRLD_XMMu32_MASKmskw_XMMu32_MEMu32_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: DISP8_MEM128 MASKOP_EVEX
5621 VPSRLD VPSRLD_XMMu32_MASKmskw_XMMu32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
5622 VPSRLD VPSRLD_XMMu32_MASKmskw_MEMu32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5623 VPSRLD VPSRLD_YMMu32_MASKmskw_YMMu32_XMMu32_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
5624 VPSRLD VPSRLD_YMMu32_MASKmskw_YMMu32_MEMu32_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: DISP8_MEM128 MASKOP_EVEX
5625 VPSRLD VPSRLD_YMMu32_MASKmskw_YMMu32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
5626 VPSRLD VPSRLD_YMMu32_MASKmskw_MEMu32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION

288 PCMPISTRM PCMPISTRM_XMMdq_MEMdq_IMMb SSE SSE4 SSE42 ATTRIBUTES: UNALIGNED
289 PCMPISTRM PCMPISTRM_XMMdq_XMMdq_IMMb SSE SSE4 SSE42 ATTRIBUTES: UNALIGNED
1044 PCMPESTRI PCMPESTRI_XMMdq_MEMdq_IMMb SSE SSE4 SSE42 ATTRIBUTES: UNALIGNED
1045 PCMPESTRI PCMPESTRI_XMMdq_XMMdq_IMMb SSE SSE4 SSE42 ATTRIBUTES: UNALIGNED
1046 PCMPESTRI PCMPESTRI_XMMdq_MEMdq_IMMb SSE SSE4 SSE42 ATTRIBUTES: UNALIGNED
1047 PCMPESTRI PCMPESTRI_XMMdq_XMMdq_IMMb SSE SSE4 SSE42 ATTRIBUTES: UNALIGNED
1056 PCMPESTRM PCMPESTRM_XMMdq_MEMdq_IMMb SSE SSE4 SSE42 ATTRIBUTES: UNALIGNED
1057 PCMPESTRM PCMPESTRM_XMMdq_XMMdq_IMMb SSE SSE4 SSE42 ATTRIBUTES: UNALIGNED
1058 PCMPESTRM PCMPESTRM_XMMdq_MEMdq_IMMb SSE SSE4 SSE42 ATTRIBUTES: UNALIGNED
1059 PCMPESTRM PCMPESTRM_XMMdq_XMMdq_IMMb SSE SSE4 SSE42 ATTRIBUTES: UNALIGNED

2974 VPCMPESTRI VPCMPESTRI_XMMdq_MEMdq_IMMb STTNI AVX AVX ATTRIBUTES:
2975 VPCMPESTRI VPCMPESTRI_XMMdq_XMMdq_IMMb STTNI AVX AVX ATTRIBUTES:
2976 VPCMPESTRI VPCMPESTRI_XMMdq_MEMdq_IMMb STTNI AVX AVX ATTRIBUTES:
2977 VPCMPESTRI VPCMPESTRI_XMMdq_XMMdq_IMMb STTNI AVX AVX ATTRIBUTES:
2978 VPCMPESTRI VPCMPESTRI_XMMdq_MEMdq_IMMb STTNI AVX AVX ATTRIBUTES:
2979 VPCMPESTRI VPCMPESTRI_XMMdq_XMMdq_IMMb STTNI AVX AVX ATTRIBUTES:
2980 VPCMPESTRM VPCMPESTRM_XMMdq_MEMdq_IMMb STTNI AVX AVX ATTRIBUTES:
2981 VPCMPESTRM VPCMPESTRM_XMMdq_XMMdq_IMMb STTNI AVX AVX ATTRIBUTES:
2982 VPCMPESTRM VPCMPESTRM_XMMdq_MEMdq_IMMb STTNI AVX AVX ATTRIBUTES:
2983 VPCMPESTRM VPCMPESTRM_XMMdq_XMMdq_IMMb STTNI AVX AVX ATTRIBUTES:
2984 VPCMPESTRM VPCMPESTRM_XMMdq_MEMdq_IMMb STTNI AVX AVX ATTRIBUTES:
2985 VPCMPESTRM VPCMPESTRM_XMMdq_XMMdq_IMMb STTNI AVX AVX ATTRIBUTES:
3103 VPCMPISTRM VPCMPISTRM_XMMdq_MEMdq_IMMb STTNI AVX AVX ATTRIBUTES:
3104 VPCMPISTRM VPCMPISTRM_XMMdq_XMMdq_IMMb STTNI AVX AVX ATTRIBUTES:

3925 VPCMPEQQ VPCMPEQQ_MASKmskw_MASKmskw_ZMMu64_ZMMu64_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
3926 VPCMPEQQ VPCMPEQQ_MASKmskw_MASKmskw_ZMMu64_MEMu64_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
3927 VPCMPEQQ VPCMPEQQ_MASKmskw_MASKmskw_XMMu64_XMMu64_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
3928 VPCMPEQQ VPCMPEQQ_MASKmskw_MASKmskw_XMMu64_MEMu64_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
3929 VPCMPEQQ VPCMPEQQ_MASKmskw_MASKmskw_YMMu64_YMMu64_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
3930 VPCMPEQQ VPCMPEQQ_MASKmskw_MASKmskw_YMMu64_MEMu64_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
3943 VPCMPEQD VPCMPEQD_MASKmskw_MASKmskw_ZMMu32_ZMMu32_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
3944 VPCMPEQD VPCMPEQD_MASKmskw_MASKmskw_ZMMu32_MEMu32_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
3945 VPCMPEQD VPCMPEQD_MASKmskw_MASKmskw_XMMu32_XMMu32_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
3946 VPCMPEQD VPCMPEQD_MASKmskw_MASKmskw_XMMu32_MEMu32_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
3947 VPCMPEQD VPCMPEQD_MASKmskw_MASKmskw_YMMu32_YMMu32_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
3948 VPCMPEQD VPCMPEQD_MASKmskw_MASKmskw_YMMu32_MEMu32_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
3956 VPCMPEQB VPCMPEQB_MASKmskw_MASKmskw_XMMu8_XMMu8_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: MASKOP_EVEX
3957 VPCMPEQB VPCMPEQB_MASKmskw_MASKmskw_XMMu8_MEMu8_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
3958 VPCMPEQB VPCMPEQB_MASKmskw_MASKmskw_YMMu8_YMMu8_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: MASKOP_EVEX
3959 VPCMPEQB VPCMPEQB_MASKmskw_MASKmskw_YMMu8_MEMu8_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
3960 VPCMPEQB VPCMPEQB_MASKmskw_MASKmskw_ZMMu8_ZMMu8_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: MASKOP_EVEX
3961 VPCMPEQB VPCMPEQB_MASKmskw_MASKmskw_ZMMu8_MEMu8_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
4362 VPCMPGTB VPCMPGTB_MASKmskw_MASKmskw_XMMu8_XMMu8_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: MASKOP_EVEX
4363 VPCMPGTB VPCMPGTB_MASKmskw_MASKmskw_XMMu8_MEMu8_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
4364 VPCMPGTB VPCMPGTB_MASKmskw_MASKmskw_YMMu8_YMMu8_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: MASKOP_EVEX
4365 VPCMPGTB VPCMPGTB_MASKmskw_MASKmskw_YMMu8_MEMu8_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
4366 VPCMPGTB VPCMPGTB_MASKmskw_MASKmskw_ZMMu8_ZMMu8_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: MASKOP_EVEX
4367 VPCMPGTB VPCMPGTB_MASKmskw_MASKmskw_ZMMu8_MEMu8_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
4388 VCMPSS VCMPSS_MASKmskw_MASKmskw_XMMf32_XMMf32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MASKOP_EVEX MXCSR SIMD_SCALAR
4389 VCMPSS VCMPSS_MASKmskw_MASKmskw_XMMf32_XMMf32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MASKOP_EVEX MXCSR SIMD_SCALAR
4390 VCMPSS VCMPSS_MASKmskw_MASKmskw_XMMf32_MEMf32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: DISP8_SCALAR MASKOP_EVEX MEMORY_FAULT_SUPPRESSION MXCSR SIMD_SCALAR
4407 VCMPSD VCMPSD_MASKmskw_MASKmskw_XMMf64_XMMf64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MASKOP_EVEX MXCSR SIMD_SCALAR
4408 VCMPSD VCMPSD_MASKmskw_MASKmskw_XMMf64_XMMf64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MASKOP_EVEX MXCSR SIMD_SCALAR
4409 VCMPSD VCMPSD_MASKmskw_MASKmskw_XMMf64_MEMf64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: DISP8_SCALAR MASKOP_EVEX MEMORY_FAULT_SUPPRESSION MXCSR SIMD_SCALAR
4808 VPCMPUW VPCMPUW_MASKmskw_MASKmskw_XMMu16_XMMu16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: MASKOP_EVEX
4809 VPCMPUW VPCMPUW_MASKmskw_MASKmskw_XMMu16_MEMu16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
4810 VPCMPUW VPCMPUW_MASKmskw_MASKmskw_YMMu16_YMMu16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: MASKOP_EVEX
4811 VPCMPUW VPCMPUW_MASKmskw_MASKmskw_YMMu16_MEMu16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
4812 VPCMPUW VPCMPUW_MASKmskw_MASKmskw_ZMMu16_ZMMu16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: MASKOP_EVEX
4813 VPCMPUW VPCMPUW_MASKmskw_MASKmskw_ZMMu16_MEMu16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5041 VCMPPS VCMPPS_MASKmskw_MASKmskw_ZMMf32_ZMMf32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX MXCSR
5042 VCMPPS VCMPPS_MASKmskw_MASKmskw_ZMMf32_ZMMf32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX MXCSR
5043 VCMPPS VCMPPS_MASKmskw_MASKmskw_ZMMf32_MEMf32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION MXCSR
5044 VCMPPS VCMPPS_MASKmskw_MASKmskw_XMMf32_XMMf32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX MXCSR
5045 VCMPPS VCMPPS_MASKmskw_MASKmskw_XMMf32_MEMf32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION MXCSR
5046 VCMPPS VCMPPS_MASKmskw_MASKmskw_YMMf32_YMMf32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX MXCSR
5047 VCMPPS VCMPPS_MASKmskw_MASKmskw_YMMf32_MEMf32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION MXCSR
5048 VCMPPD VCMPPD_MASKmskw_MASKmskw_ZMMf64_ZMMf64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX MXCSR
5049 VCMPPD VCMPPD_MASKmskw_MASKmskw_ZMMf64_ZMMf64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX MXCSR
5050 VCMPPD VCMPPD_MASKmskw_MASKmskw_ZMMf64_MEMf64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION MXCSR
5051 VCMPPD VCMPPD_MASKmskw_MASKmskw_XMMf64_XMMf64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX MXCSR
5052 VCMPPD VCMPPD_MASKmskw_MASKmskw_XMMf64_MEMf64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION MXCSR
5053 VCMPPD VCMPPD_MASKmskw_MASKmskw_YMMf64_YMMf64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX MXCSR
5054 VCMPPD VCMPPD_MASKmskw_MASKmskw_YMMf64_MEMf64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION MXCSR
5111 VPCMPW VPCMPW_MASKmskw_MASKmskw_XMMi16_XMMi16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: MASKOP_EVEX
5112 VPCMPW VPCMPW_MASKmskw_MASKmskw_XMMi16_MEMi16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5113 VPCMPW VPCMPW_MASKmskw_MASKmskw_YMMi16_YMMi16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: MASKOP_EVEX
5114 VPCMPW VPCMPW_MASKmskw_MASKmskw_YMMi16_MEMi16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5115 VPCMPW VPCMPW_MASKmskw_MASKmskw_ZMMi16_ZMMi16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: MASKOP_EVEX
5116 VPCMPW VPCMPW_MASKmskw_MASKmskw_ZMMi16_MEMi16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5117 VPCMPQ VPCMPQ_MASKmskw_MASKmskw_ZMMi64_ZMMi64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
5118 VPCMPQ VPCMPQ_MASKmskw_MASKmskw_ZMMi64_MEMi64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5119 VPCMPQ VPCMPQ_MASKmskw_MASKmskw_XMMi64_XMMi64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
5120 VPCMPQ VPCMPQ_MASKmskw_MASKmskw_XMMi64_MEMi64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5121 VPCMPQ VPCMPQ_MASKmskw_MASKmskw_YMMi64_YMMi64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
5122 VPCMPQ VPCMPQ_MASKmskw_MASKmskw_YMMi64_MEMi64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5135 VPCMPD VPCMPD_MASKmskw_MASKmskw_ZMMi32_ZMMi32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
5136 VPCMPD VPCMPD_MASKmskw_MASKmskw_ZMMi32_MEMi32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5137 VPCMPD VPCMPD_MASKmskw_MASKmskw_XMMi32_XMMi32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
5138 VPCMPD VPCMPD_MASKmskw_MASKmskw_XMMi32_MEMi32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5139 VPCMPD VPCMPD_MASKmskw_MASKmskw_YMMi32_YMMi32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
5140 VPCMPD VPCMPD_MASKmskw_MASKmskw_YMMi32_MEMi32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5141 VPCMPB VPCMPB_MASKmskw_MASKmskw_XMMi8_XMMi8_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: MASKOP_EVEX
5142 VPCMPB VPCMPB_MASKmskw_MASKmskw_XMMi8_MEMi8_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5143 VPCMPB VPCMPB_MASKmskw_MASKmskw_YMMi8_YMMi8_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: MASKOP_EVEX
5144 VPCMPB VPCMPB_MASKmskw_MASKmskw_YMMi8_MEMi8_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5145 VPCMPB VPCMPB_MASKmskw_MASKmskw_ZMMi8_ZMMi8_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: MASKOP_EVEX
5146 VPCMPB VPCMPB_MASKmskw_MASKmskw_ZMMi8_MEMi8_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5222 VPCMPUQ VPCMPUQ_MASKmskw_MASKmskw_ZMMu64_ZMMu64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
5223 VPCMPUQ VPCMPUQ_MASKmskw_MASKmskw_ZMMu64_MEMu64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5224 VPCMPUQ VPCMPUQ_MASKmskw_MASKmskw_XMMu64_XMMu64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
5225 VPCMPUQ VPCMPUQ_MASKmskw_MASKmskw_XMMu64_MEMu64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5226 VPCMPUQ VPCMPUQ_MASKmskw_MASKmskw_YMMu64_YMMu64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
5227 VPCMPUQ VPCMPUQ_MASKmskw_MASKmskw_YMMu64_MEMu64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5243 VPCMPUB VPCMPUB_MASKmskw_MASKmskw_XMMu8_XMMu8_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: MASKOP_EVEX
5244 VPCMPUB VPCMPUB_MASKmskw_MASKmskw_XMMu8_MEMu8_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5245 VPCMPUB VPCMPUB_MASKmskw_MASKmskw_YMMu8_YMMu8_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: MASKOP_EVEX
5246 VPCMPUB VPCMPUB_MASKmskw_MASKmskw_YMMu8_MEMu8_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5247 VPCMPUB VPCMPUB_MASKmskw_MASKmskw_ZMMu8_ZMMu8_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: MASKOP_EVEX
5248 VPCMPUB VPCMPUB_MASKmskw_MASKmskw_ZMMu8_MEMu8_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5258 VPCMPUD VPCMPUD_MASKmskw_MASKmskw_ZMMu32_ZMMu32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
5259 VPCMPUD VPCMPUD_MASKmskw_MASKmskw_ZMMu32_MEMu32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5260 VPCMPUD VPCMPUD_MASKmskw_MASKmskw_XMMu32_XMMu32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
5261 VPCMPUD VPCMPUD_MASKmskw_MASKmskw_XMMu32_MEMu32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5262 VPCMPUD VPCMPUD_MASKmskw_MASKmskw_YMMu32_YMMu32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
5263 VPCMPUD VPCMPUD_MASKmskw_MASKmskw_YMMu32_MEMu32_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5677 VPCMPEQW VPCMPEQW_MASKmskw_MASKmskw_XMMu16_XMMu16_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: MASKOP_EVEX
5678 VPCMPEQW VPCMPEQW_MASKmskw_MASKmskw_XMMu16_MEMu16_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5679 VPCMPEQW VPCMPEQW_MASKmskw_MASKmskw_YMMu16_YMMu16_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: MASKOP_EVEX
5680 VPCMPEQW VPCMPEQW_MASKmskw_MASKmskw_YMMu16_MEMu16_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5681 VPCMPEQW VPCMPEQW_MASKmskw_MASKmskw_ZMMu16_ZMMu16_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: MASKOP_EVEX
5682 VPCMPEQW VPCMPEQW_MASKmskw_MASKmskw_ZMMu16_MEMu16_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
6222 VPCMPGTD VPCMPGTD_MASKmskw_MASKmskw_ZMMi32_ZMMi32_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
6223 VPCMPGTD VPCMPGTD_MASKmskw_MASKmskw_ZMMi32_MEMi32_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
6224 VPCMPGTD VPCMPGTD_MASKmskw_MASKmskw_XMMi32_XMMi32_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
6225 VPCMPGTD VPCMPGTD_MASKmskw_MASKmskw_XMMi32_MEMi32_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
6226 VPCMPGTD VPCMPGTD_MASKmskw_MASKmskw_YMMi32_YMMi32_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
6227 VPCMPGTD VPCMPGTD_MASKmskw_MASKmskw_YMMi32_MEMi32_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
6237 VPCMPGTQ VPCMPGTQ_MASKmskw_MASKmskw_ZMMi64_ZMMi64_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
6238 VPCMPGTQ VPCMPGTQ_MASKmskw_MASKmskw_ZMMi64_MEMi64_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
6239 VPCMPGTQ VPCMPGTQ_MASKmskw_MASKmskw_XMMi64_XMMi64_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
6240 VPCMPGTQ VPCMPGTQ_MASKmskw_MASKmskw_XMMi64_MEMi64_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
6241 VPCMPGTQ VPCMPGTQ_MASKmskw_MASKmskw_YMMi64_YMMi64_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
6242 VPCMPGTQ VPCMPGTQ_MASKmskw_MASKmskw_YMMi64_MEMi64_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
6253 VPCMPGTW VPCMPGTW_MASKmskw_MASKmskw_XMMu16_XMMu16_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: MASKOP_EVEX
6254 VPCMPGTW VPCMPGTW_MASKmskw_MASKmskw_XMMu16_MEMu16_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
6255 VPCMPGTW VPCMPGTW_MASKmskw_MASKmskw_YMMu16_YMMu16_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: MASKOP_EVEX
6256 VPCMPGTW VPCMPGTW_MASKmskw_MASKmskw_YMMu16_MEMu16_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
6257 VPCMPGTW VPCMPGTW_MASKmskw_MASKmskw_ZMMu16_ZMMu16_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: MASKOP_EVEX
6258 VPCMPGTW VPCMPGTW_MASKmskw_MASKmskw_ZMMu16_MEMu16_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
 */

namespace {
template <typename D, typename S1, typename S2>
DEF_SEM(MINSS, D dst, S1 src1, S2 src2) {
  auto dest_vec = FReadV32(src1);
  auto src1_float = FExtractV32(dest_vec, 0);
  auto src2_float = FExtractV32(FReadV32(src2), 0);

  auto min = src1_float;

  // If either float is a NaN (SNaN or QNaN):
  if (std::isunordered(src1_float, src2_float)) {
    min = src2_float;
  }
  // or if both floats are 0.0:
  else if ((src1_float == 0.0) && (src2_float == 0.0)) {
    min = src2_float;
  }
  // or if src2 is less than src1:
  else if (src1_float >= src2_float) {
    min = src2_float;
  }

  dest_vec = FInsertV32(dest_vec, 0, min);
  FWriteV32(dst, dest_vec);  // SSE: Writes to XMM, AVX: Zero-extends XMM.
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(MINSD, D dst, S1 src1, S2 src2) {
  auto dest_vec = FReadV64(src1);
  auto src1_float = FExtractV64(dest_vec, 0);
  auto src2_float = FExtractV64(FReadV64(src2), 0);

  auto min = src1_float;

  // If either float is a NaN (SNaN or QNaN):
  if (std::isunordered(src1_float, src2_float)) {
    min = src2_float;
  }
  // or if both floats are 0.0:
  else if ((src1_float == 0.0) && (src2_float == 0.0)) {
    min = src2_float;
  }
  // or if src2 is less than src1:
  else if (src1_float >= src2_float) {
    min = src2_float;
  }

  dest_vec = FInsertV64(dest_vec, 0, min);
  FWriteV64(dst, dest_vec);  // SSE: Writes to XMM, AVX: Zero-extends XMM.
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(MAXSS, D dst, S1 src1, S2 src2) {
  auto dest_vec = FReadV32(src1);
  auto src1_float = FExtractV32(dest_vec, 0);
  auto src2_float = FExtractV32(FReadV32(src2), 0);

  auto max = src1_float;

  // If either float is a NaN (SNaN or QNaN):
  if (std::isunordered(src1_float, src2_float)) {
    max = src2_float;
  }
  // or if both floats are 0.0:
  else if ((src1_float == 0.0) && (src2_float == 0.0)) {
    max = src2_float;
  }
  // or if src2 is greater than src1:
  else if (src1_float < src2_float) {
    max = src2_float;
  }

  dest_vec = FInsertV32(dest_vec, 0, max);
  FWriteV32(dst, dest_vec);  // SSE: Writes to XMM, AVX: Zero-extends XMM.
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(MAXSD, D dst, S1 src1, S2 src2) {
  auto dest_vec = FReadV64(src1);
  auto src1_float = FExtractV64(dest_vec, 0);
  auto src2_float = FExtractV64(FReadV64(src2), 0);

  auto max = src1_float;

  // If either float is a NaN (SNaN or QNaN):
  if (std::isunordered(src1_float, src2_float)) {
    max = src2_float;
  }
  // or if both floats are 0.0:
  else if ((src1_float == 0.0) && (src2_float == 0.0)) {
    max = src2_float;
  }
  // or if src2 is greater than src1:
  else if (src1_float < src2_float) {
    max = src2_float;
  }

  dest_vec = FInsertV64(dest_vec, 0, max);
  FWriteV64(dst, dest_vec);  // SSE: Writes to XMM, AVX: Zero-extends XMM.
  return memory;
}

}  // namespace

DEF_ISEL(MINSS_XMMss_MEMss) = MINSS<V128W, V128, MV32>;
DEF_ISEL(MINSS_XMMss_XMMss) = MINSS<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VMINSS_XMMdq_XMMdq_MEMd) = MINSS<VV128W, V128, MV32>;)
IF_AVX(DEF_ISEL(VMINSS_XMMdq_XMMdq_XMMd) = MINSS<VV128W, V128, V128>;)
/*
5112 VMINSS VMINSS_XMMf32_MASKmskw_XMMf32_XMMf32_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MASKOP_EVEX MXCSR SIMD_SCALAR
5113 VMINSS VMINSS_XMMf32_MASKmskw_XMMf32_XMMf32_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MASKOP_EVEX MXCSR SIMD_SCALAR
5114 VMINSS VMINSS_XMMf32_MASKmskw_XMMf32_MEMf32_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: DISP8_SCALAR MASKOP_EVEX MEMORY_FAULT_SUPPRESSION MXCSR SIMD_SCALAR
*/

DEF_ISEL(MINSD_XMMsd_MEMsd) = MINSD<V128W, V128, MV64>;
DEF_ISEL(MINSD_XMMsd_XMMsd) = MINSD<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VMINSD_XMMdq_XMMdq_MEMq) = MINSD<VV128W, V128, MV64>;)
IF_AVX(DEF_ISEL(VMINSD_XMMdq_XMMdq_XMMq) = MINSD<VV128W, V128, V128>;)
/*
634 PMINSD PMINSD_XMMdq_MEMdq SSE SSE4 SSE4 ATTRIBUTES: REQUIRES_ALIGNMENT
635 PMINSD PMINSD_XMMdq_XMMdq SSE SSE4 SSE4 ATTRIBUTES: REQUIRES_ALIGNMENT

2385 VPMINSD VPMINSD_XMMdq_XMMdq_MEMdq AVX AVX AVX ATTRIBUTES:
2386 VPMINSD VPMINSD_XMMdq_XMMdq_XMMdq AVX AVX AVX ATTRIBUTES:
2387 VPMINSD VPMINSD_YMMqq_YMMqq_MEMqq AVX2 AVX2 AVX2 ATTRIBUTES:
2388 VPMINSD VPMINSD_YMMqq_YMMqq_YMMqq AVX2 AVX2 AVX2 ATTRIBUTES:

4210 VPMINSD VPMINSD_ZMMi32_MASKmskw_ZMMi32_ZMMi32_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
4211 VPMINSD VPMINSD_ZMMi32_MASKmskw_ZMMi32_MEMi32_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
4212 VPMINSD VPMINSD_XMMi32_MASKmskw_XMMi32_XMMi32_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
4213 VPMINSD VPMINSD_XMMi32_MASKmskw_XMMi32_MEMi32_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
4214 VPMINSD VPMINSD_YMMi32_MASKmskw_YMMi32_YMMi32_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
4215 VPMINSD VPMINSD_YMMi32_MASKmskw_YMMi32_MEMi32_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION

5143 VMINSD VMINSD_XMMf64_MASKmskw_XMMf64_XMMf64_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MASKOP_EVEX MXCSR SIMD_SCALAR
5144 VMINSD VMINSD_XMMf64_MASKmskw_XMMf64_XMMf64_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MASKOP_EVEX MXCSR SIMD_SCALAR
5145 VMINSD VMINSD_XMMf64_MASKmskw_XMMf64_MEMf64_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: DISP8_SCALAR MASKOP_EVEX MEMORY_FAULT_SUPPRESSION MXCSR SIMD_SCALAR
*/

DEF_ISEL(MAXSS_XMMss_MEMss) = MAXSS<V128W, V128, MV32>;
DEF_ISEL(MAXSS_XMMss_XMMss) = MAXSS<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VMAXSS_XMMdq_XMMdq_MEMd) = MAXSS<VV128W, V128, MV128>;)
IF_AVX(DEF_ISEL(VMAXSS_XMMdq_XMMdq_XMMd) = MAXSS<VV128W, V128, V128>;)
/*
3958 VMAXSS VMAXSS_XMMf32_MASKmskw_XMMf32_XMMf32_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MASKOP_EVEX MXCSR SIMD_SCALAR
3959 VMAXSS VMAXSS_XMMf32_MASKmskw_XMMf32_XMMf32_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MASKOP_EVEX MXCSR SIMD_SCALAR
3960 VMAXSS VMAXSS_XMMf32_MASKmskw_XMMf32_MEMf32_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: DISP8_SCALAR MASKOP_EVEX MEMORY_FAULT_SUPPRESSION MXCSR SIMD_SCALAR
*/

DEF_ISEL(MAXSD_XMMsd_MEMsd) = MAXSD<V128W, V128, MV64>;
DEF_ISEL(MAXSD_XMMsd_XMMsd) = MAXSD<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VMAXSD_XMMdq_XMMdq_MEMq) = MAXSD<VV128W, V128, MV64>;)
IF_AVX(DEF_ISEL(VMAXSD_XMMdq_XMMdq_XMMq) = MAXSD<VV128W, V128, V128>;)
/*
794 PMAXSD PMAXSD_XMMdq_MEMdq SSE SSE4 SSE4 ATTRIBUTES: REQUIRES_ALIGNMENT
795 PMAXSD PMAXSD_XMMdq_XMMdq SSE SSE4 SSE4 ATTRIBUTES: REQUIRES_ALIGNMENT

2299 VPMAXSD VPMAXSD_XMMdq_XMMdq_MEMdq AVX AVX AVX ATTRIBUTES:
2300 VPMAXSD VPMAXSD_XMMdq_XMMdq_XMMdq AVX AVX AVX ATTRIBUTES:
2301 VPMAXSD VPMAXSD_YMMqq_YMMqq_MEMqq AVX2 AVX2 AVX2 ATTRIBUTES:
2302 VPMAXSD VPMAXSD_YMMqq_YMMqq_YMMqq AVX2 AVX2 AVX2 ATTRIBUTES:

4029 VPMAXSD VPMAXSD_ZMMi32_MASKmskw_ZMMi32_ZMMi32_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
4030 VPMAXSD VPMAXSD_ZMMi32_MASKmskw_ZMMi32_MEMi32_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
4031 VPMAXSD VPMAXSD_XMMi32_MASKmskw_XMMi32_XMMi32_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
4032 VPMAXSD VPMAXSD_XMMi32_MASKmskw_XMMi32_MEMi32_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
4033 VPMAXSD VPMAXSD_YMMi32_MASKmskw_YMMi32_YMMi32_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
4034 VPMAXSD VPMAXSD_YMMi32_MASKmskw_YMMi32_MEMi32_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION

4207 VMAXSD VMAXSD_XMMf64_MASKmskw_XMMf64_XMMf64_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MASKOP_EVEX MXCSR SIMD_SCALAR
4208 VMAXSD VMAXSD_XMMf64_MASKmskw_XMMf64_XMMf64_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MASKOP_EVEX MXCSR SIMD_SCALAR
4209 VMAXSD VMAXSD_XMMf64_MASKmskw_XMMf64_MEMf64_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: DISP8_SCALAR MASKOP_EVEX MEMORY_FAULT_SUPPRESSION MXCSR SIMD_SCALAR
*/

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(MINPS, D dst, S1 src1, S2 src2) {
  auto dest_vec = FReadV32(src1);
  auto src2_vec = FReadV32(src2);

  auto vec_count = NumVectorElems(src2_vec);
  _Pragma("unroll") for (std::size_t i = 0; i < vec_count; i++) {
    auto v1 = FExtractV32(dest_vec, i);
    auto v2 = FExtractV32(src2_vec, i);

    auto min = v1;

    // If either float is a NaN (SNaN or QNaN):
    if (__builtin_isunordered(v1, v2)) {
      min = v2;

    // or if both floats are 0.0:
    } else if ((v1 == 0.0) && (v2 == 0.0)) {
      min = v2;

    // or if src2 is less than src1:
    } else if (__builtin_isless(v2, v1)) {
      min = v2;
    }

    dest_vec = FInsertV32(dest_vec, i, min);
  }
  FWriteV32(dst, dest_vec);  // SSE: Writes to XMM, AVX: Zero-extends XMM.
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(MAXPS, D dst, S1 src1, S2 src2) {
  auto dest_vec = FReadV32(src1);
  auto src2_vec = FReadV32(src2);

  auto vec_count = NumVectorElems(src2_vec);
  _Pragma("unroll") for (std::size_t i = 0; i < vec_count; i++) {
    auto v1 = FExtractV32(dest_vec, i);
    auto v2 = FExtractV32(src2_vec, i);

    auto max = v1;

    // If either float is a NaN (SNaN or QNaN):
    if (__builtin_isunordered(v1, v2)) {
      max = v2;

    // or if both floats are 0.0:
    } else if ((v1 == 0.0) && (v2 == 0.0)) {
      max = v2;

    // or if src2 is greater than src1:
    } else if (__builtin_isgreater(v2, v1)) {
      max = v2;
    }

    dest_vec = FInsertV32(dest_vec, i, max);
  }
  FWriteV32(dst, dest_vec);  // SSE: Writes to XMM, AVX: Zero-extends XMM.
  return memory;
}

}  // namespace

DEF_ISEL(MINPS_XMMps_MEMps) = MINPS<V128W, V128, MV128>;
DEF_ISEL(MINPS_XMMps_XMMps) = MINPS<V128W, V128, V128>;

DEF_ISEL(MAXPS_XMMps_XMMps) = MAXPS<V128W, V128, V128>;
DEF_ISEL(MAXPS_XMMps_MEMps) = MAXPS<V128W, V128, MV128>;

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(UNPCKLPS, D dst, S1 src1, S2 src2) {

  // Initialize with a copy of src1 as a vector of 32-bit (DWORD) floats:
  auto temp_vec = FReadV32(src1);

  // The "unpack" of DWORD src1[31:0] into dest[31:0] is omitted here because
  // it is done implicitly in the copying of src1, above.

  // "Unpack" of DWORD src1[63:32] into dest[95:64]:
  auto src1_float = FExtractV32(temp_vec, 1);
  temp_vec = FInsertV32(temp_vec, 2, src1_float);

  // Treat src2 as a vector of 32-bit (DWORD) floats:
  auto src2_vec = FReadV32(src2);

  // "Unpack" of DWORD src2[31:0] into dest[63:32]:
  auto src2_float = FExtractV32(src2_vec, 0);
  temp_vec = FInsertV32(temp_vec, 1, src2_float);

  // "Unpack" of DWORD src2[63:32] into dest[127:96]:
  src2_float = FExtractV32(src2_vec, 1);
  temp_vec = FInsertV32(temp_vec, 3, src2_float);

  FWriteV32(dst, temp_vec);  // SSE: Writes to XMM, AVX: Zero-extends XMM.
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(UNPCKLPD, D dst, S1 src1, S2 src2) {

  // Initialize with a copy of src1 as a vector of 64-bit (QWORD) floats:
  auto temp_vec = FReadV64(src1);

  // The "unpack" of low QWORD of src1 into low QWORD of dest is omitted here
  // because it is done implicitly in the copying of src1.

  // Treat src2 as a vector of 64-bit (QWORD) floats:
  auto src2_vec = FReadV64(src2);
  auto src2_float = FExtractV64(src2_vec, 0);  // "unpack" low QWORD of src2
  temp_vec = FInsertV64(temp_vec, 1, src2_float);  //   into high QWORD of dest

  FWriteV64(dst, temp_vec);  // SSE: Writes to XMM, AVX: Zero-extends XMM.
  return memory;
}

}  // namespace

DEF_ISEL(UNPCKLPS_XMMps_MEMdq) = UNPCKLPS<V128W, V128, MV64>;
DEF_ISEL(UNPCKLPS_XMMps_XMMq) = UNPCKLPS<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VUNPCKLPS_XMMdq_XMMdq_MEMdq) = UNPCKLPS<VV128W, V128, MV64>;)
IF_AVX(DEF_ISEL(VUNPCKLPS_XMMdq_XMMdq_XMMdq) = UNPCKLPS<VV128W, V128, V128>;)
/*
IF_AVX(DEF_ISEL(VUNPCKLPS_YMMqq_YMMqq_MEMqq) = UNPCKLPS<VV256W, V256, MV128>;)
IF_AVX(DEF_ISEL(VUNPCKLPS_YMMqq_YMMqq_YMMqq) = UNPCKLPS<VV256W, V256, V256>;)

6156 VUNPCKLPS VUNPCKLPS_ZMMf32_MASKmskw_ZMMf32_ZMMf32_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
6157 VUNPCKLPS VUNPCKLPS_ZMMf32_MASKmskw_ZMMf32_MEMf32_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX
6158 VUNPCKLPS VUNPCKLPS_XMMf32_MASKmskw_XMMf32_XMMf32_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
6159 VUNPCKLPS VUNPCKLPS_XMMf32_MASKmskw_XMMf32_MEMf32_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX
6160 VUNPCKLPS VUNPCKLPS_YMMf32_MASKmskw_YMMf32_YMMf32_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
6161 VUNPCKLPS VUNPCKLPS_YMMf32_MASKmskw_YMMf32_MEMf32_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX
*/

DEF_ISEL(UNPCKLPD_XMMpd_MEMdq) = UNPCKLPD<V128W, V128, MV64>;
DEF_ISEL(UNPCKLPD_XMMpd_XMMq) = UNPCKLPD<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VUNPCKLPD_XMMdq_XMMdq_MEMdq) = UNPCKLPD<VV128W, V128, MV64>;)
IF_AVX(DEF_ISEL(VUNPCKLPD_XMMdq_XMMdq_XMMdq) = UNPCKLPD<VV128W, V128, V128>;)
/*
IF_AVX(DEF_ISEL(VUNPCKLPD_YMMqq_YMMqq_MEMqq) = UNPCKLPD<VV256W, V256, MV128>;)
IF_AVX(DEF_ISEL(VUNPCKLPD_YMMqq_YMMqq_YMMqq) = UNPCKLPD<VV256W, V256, V256>;)

6177 VUNPCKLPD VUNPCKLPD_ZMMf64_MASKmskw_ZMMf64_ZMMf64_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
6178 VUNPCKLPD VUNPCKLPD_ZMMf64_MASKmskw_ZMMf64_MEMf64_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX
6179 VUNPCKLPD VUNPCKLPD_XMMf64_MASKmskw_XMMf64_XMMf64_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
6180 VUNPCKLPD VUNPCKLPD_XMMf64_MASKmskw_XMMf64_MEMf64_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX
6181 VUNPCKLPD VUNPCKLPD_YMMf64_MASKmskw_YMMf64_YMMf64_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
6182 VUNPCKLPD VUNPCKLPD_YMMf64_MASKmskw_YMMf64_MEMf64_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX
*/

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(UNPCKHPS, D dst, S1 src1, S2 src2) {

  // Treating src1 as another vector of 32-bit DWORDs:
  auto src1_vec = FReadV32(src1);
  auto src2_vec = FReadV32(src2);

  auto res = FClearV32(FReadV32(dst));

  res = FInsertV32(res, 0, FExtractV32(src1_vec, 2));
  res = FInsertV32(res, 1, FExtractV32(src2_vec, 2));
  res = FInsertV32(res, 2, FExtractV32(src1_vec, 3));
  res = FInsertV32(res, 3, FExtractV32(src2_vec, 3));

  FWriteV32(dst, res);  // SSE: Writes to XMM, AVX: Zero-extends XMM.
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(UNPCKHPD, D dst, S1 src1, S2 src2) {

  // Initialize a working copy of src2 as a vector of 64-bit QWORDs.
  // This also accomplishes the "unpack" of the high QWORD of src2:
  auto temp_vec = FReadV64(src2);

  // Treating src1 as another vector of 64-bit QWORDs:
  auto src1_vec = FReadV64(src1);
  auto src1_high_qword =
      FExtractV64(src1_vec, 1);  // "unpack" high QWORD of src1
  temp_vec =
      FInsertV64(temp_vec, 0, src1_high_qword);  //   into low QWORD of temp

  FWriteV64(dst, temp_vec);  // SSE: Writes to XMM, AVX: Zero-extends XMM.
  return memory;
}

}  // namespace

DEF_ISEL(UNPCKHPD_XMMpd_MEMdq) = UNPCKHPD<V128W, V128, MV128>;
DEF_ISEL(UNPCKHPD_XMMpd_XMMq) = UNPCKHPD<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VUNPCKHPD_XMMdq_XMMdq_MEMdq) = UNPCKHPD<VV128W, V128, MV128>;)
IF_AVX(DEF_ISEL(VUNPCKHPD_XMMdq_XMMdq_XMMdq) = UNPCKHPD<VV128W, V128, V128>;)

DEF_ISEL(UNPCKHPS_XMMps_MEMdq) = UNPCKHPS<V128W, V128, MV128>;
DEF_ISEL(UNPCKHPS_XMMps_XMMdq) = UNPCKHPS<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VUNPCKHPS_XMMdq_XMMdq_MEMdq) = UNPCKHPS<VV128W, V128, MV128>;)
IF_AVX(DEF_ISEL(VUNPCKHPS_XMMdq_XMMdq_XMMdq) = UNPCKHPS<VV128W, V128, V128>;)

/*
2440 VUNPCKHPD VUNPCKHPD_YMMqq_YMMqq_MEMqq AVX AVX AVX ATTRIBUTES:
2441 VUNPCKHPD VUNPCKHPD_YMMqq_YMMqq_YMMqq AVX AVX AVX ATTRIBUTES:
4319 VUNPCKHPD VUNPCKHPD_ZMMf64_MASKmskw_ZMMf64_ZMMf64_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
4320 VUNPCKHPD VUNPCKHPD_ZMMf64_MASKmskw_ZMMf64_MEMf64_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX
4321 VUNPCKHPD VUNPCKHPD_XMMf64_MASKmskw_XMMf64_XMMf64_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
4322 VUNPCKHPD VUNPCKHPD_XMMf64_MASKmskw_XMMf64_MEMf64_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX
4323 VUNPCKHPD VUNPCKHPD_YMMf64_MASKmskw_YMMf64_YMMf64_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
4324 VUNPCKHPD VUNPCKHPD_YMMf64_MASKmskw_YMMf64_MEMf64_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX
*/

namespace {

template <typename D, typename S1>
DEF_SEM(MOVDDUP, D dst, S1 src) {

  // Treat src as a vector of QWORD (64-bit) floats, even if it's just one element:
  auto src_vec = FReadV64(src);

  // "Move and duplicate" QWORD src[63:0] into dest[63:0] and into dest[127:64]:
  auto src_float = FExtractV64(src_vec, 0);

  float64v2_t temp_vec =
      {};  // length of src and dest may differ, so manually create.
  temp_vec = FInsertV64(temp_vec, 0, src_float);
  temp_vec = FInsertV64(temp_vec, 1, src_float);

  // SSE: Writes to XMM (dest[MAXVL-1:127] unmodified). AVX: Zero-extends XMM.
  FWriteV64(dst, temp_vec);
  return memory;
}

}  // namespace

DEF_ISEL(MOVDDUP_XMMdq_MEMq) = MOVDDUP<V128W, MV64>;
DEF_ISEL(MOVDDUP_XMMdq_XMMq) = MOVDDUP<V128W, V128>;
IF_AVX(DEF_ISEL(VMOVDDUP_XMMdq_MEMq) = MOVDDUP<VV128W, MV64>;)
IF_AVX(DEF_ISEL(VMOVDDUP_XMMdq_XMMdq) = MOVDDUP<VV128W, V128>;)
/*
2320 VMOVDDUP VMOVDDUP_YMMqq_MEMqq DATAXFER AVX AVX ATTRIBUTES:
2321 VMOVDDUP VMOVDDUP_YMMqq_YMMqq DATAXFER AVX AVX ATTRIBUTES:
4070 VMOVDDUP VMOVDDUP_ZMMf64_MASKmskw_ZMMf64_AVX512 DATAXFER AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
4071 VMOVDDUP VMOVDDUP_ZMMf64_MASKmskw_MEMf64_AVX512 DATAXFER AVX512EVEX AVX512F_512 ATTRIBUTES: DISP8_MOVDDUP MASKOP_EVEX
4072 VMOVDDUP VMOVDDUP_XMMf64_MASKmskw_XMMf64_AVX512 DATAXFER AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
4073 VMOVDDUP VMOVDDUP_XMMf64_MASKmskw_MEMf64_AVX512 DATAXFER AVX512EVEX AVX512F_128 ATTRIBUTES: DISP8_MOVDDUP MASKOP_EVEX
4074 VMOVDDUP VMOVDDUP_YMMf64_MASKmskw_YMMf64_AVX512 DATAXFER AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
4075 VMOVDDUP VMOVDDUP_YMMf64_MASKmskw_MEMf64_AVX512 DATAXFER AVX512EVEX AVX512F_256 ATTRIBUTES: DISP8_MOVDDUP MASKOP_EVEX
*/

namespace {

template <typename D, typename S1>
DEF_SEM(SQRTSS, D dst, S1 src1) {

  // Extract a "single-precision" (32-bit) float from [31:0] of src1 vector:
  auto src_float = FExtractV32(FReadV32(src1), 0);

  // Store the square root result in dest[32:0]:
  auto square_root = SquareRoot32(memory, state, src_float);
  auto temp_vec = FReadV32(dst);  // initialize a destination vector
  temp_vec = FInsertV32(temp_vec, 0, square_root);

  // Write out the result and return memory state:
  FWriteV32(dst, temp_vec);  // SSE: Writes to XMM, AVX: Zero-extends XMM.
  return memory;
}

template <typename D, typename S1>
DEF_SEM(RSQRTSS, D dst, S1 src1) {

  // Extract a "single-precision" (32-bit) float from [31:0] of src1 vector:
  auto src_float = FExtractV32(FReadV32(src1), 0);

  // Store the square root result in dest[32:0]:
  auto square_root = SquareRoot32(memory, state, src_float);
  auto temp_vec = FReadV32(dst);  // initialize a destination vector
  temp_vec = FInsertV32(temp_vec, 0, FDiv(1.0f, square_root));

  // Write out the result and return memory state:
  FWriteV32(dst, temp_vec);  // SSE: Writes to XMM, AVX: Zero-extends XMM.
  return memory;
}

#if HAS_FEATURE_AVX
template <typename D, typename S1, typename S2>
DEF_SEM(VSQRTSS, D dst, S1 src1, S2 src2) {

  // Extract the single-precision float from [31:0] of the src2 vector:
  auto src_float = FExtractV32(FReadV32(src2), 0);

  // Initialize dest vector, while also copying src1[127:32] -> dst[127:32].
  auto temp_vec = FReadV32(src1);

  // Store the square root result in dest[31:0]:
  auto square_root = SquareRoot32(memory, state, src_float);
  temp_vec = FInsertV32(temp_vec, 0, square_root);

  // Write out the result and return memory state:
  FWriteV32(dst, temp_vec);  // SSE: Writes to XMM, AVX: Zero-extends XMM.
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(VRSQRTSS, D dst, S1 src1, S2 src2) {

  // Extract the single-precision float from [31:0] of the src2 vector:
  auto src_float = FExtractV32(FReadV32(src2), 0);

  // Initialize dest vector, while also copying src1[127:32] -> dst[127:32].
  auto temp_vec = FReadV32(src1);

  // Store the square root result in dest[31:0]:
  auto square_root = SquareRoot32(memory, state, src_float);
  temp_vec = FInsertV32(temp_vec, 0, FDiv(1.0f, square_root));

  // Write out the result and return memory state:
  FWriteV32(dst, temp_vec);  // SSE: Writes to XMM, AVX: Zero-extends XMM.
  return memory;
}
#endif  // HAS_FEATURE_AVX
}  // namespace

DEF_ISEL(SQRTSS_XMMss_MEMss) = SQRTSS<V128W, MV32>;
DEF_ISEL(SQRTSS_XMMss_XMMss) = SQRTSS<V128W, V128>;
IF_AVX(DEF_ISEL(VSQRTSS_XMMdq_XMMdq_MEMd) = VSQRTSS<VV128W, V128, MV32>;)
IF_AVX(DEF_ISEL(VSQRTSS_XMMdq_XMMdq_XMMd) = VSQRTSS<VV128W, V128, V128>;)
/*
4316 VSQRTSS VSQRTSS_XMMf32_MASKmskw_XMMf32_XMMf32_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MASKOP_EVEX MXCSR SIMD_SCALAR
4317 VSQRTSS VSQRTSS_XMMf32_MASKmskw_XMMf32_XMMf32_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MASKOP_EVEX MXCSR SIMD_SCALAR
4318 VSQRTSS VSQRTSS_XMMf32_MASKmskw_XMMf32_MEMf32_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: DISP8_SCALAR MASKOP_EVEX MEMORY_FAULT_SUPPRESSION MXCSR SIMD_SCALAR
*/

DEF_ISEL(RSQRTSS_XMMss_MEMss) = RSQRTSS<V128W, MV32>;
DEF_ISEL(RSQRTSS_XMMss_XMMss) = RSQRTSS<V128W, V128>;
IF_AVX(DEF_ISEL(VRSQRTSS_XMMdq_XMMdq_MEMd) = VRSQRTSS<VV128W, V128, MV32>;)
IF_AVX(DEF_ISEL(VRSQRTSS_XMMdq_XMMdq_XMMd) = VRSQRTSS<VV128W, V128, V128>;)

namespace {

DEF_HELPER(SquareRoot64, float64_t src_float)->float64_t {
  auto square_root = src_float;

  // Special cases for invalid square root operations. See Intel manual, Table E-10.
  if (IsNaN(src_float)) {

    // If src is SNaN, return the SNaN converted to a QNaN:
    if (IsSignalingNaN(src_float)) {
      nan64_t temp_nan = {src_float};
      temp_nan.is_quiet_nan =
          1;  // equivalent to a bitwise OR with 0x0008000000000000
      square_root = temp_nan.d;

    // Else, src is a QNaN. Pass it directly to the result:
    } else {
      square_root = src_float;
    }
  } else {  // a number, that is, not a NaN

    // A negative operand (except -0.0) results in the QNaN indefinite value.
    if (IsNegative(src_float) && src_float != -0.0) {
      uint64_t indef_qnan = 0xFFF8000000000000ULL;
      square_root = reinterpret_cast<float64_t &>(indef_qnan);
    } else {
      square_root = std::sqrt(src_float);
    }
  }

  return square_root;
}

template <typename D, typename S1>
DEF_SEM(SQRTSD, D dst, S1 src1) {

  // Extract a "double-precision" (64-bit) float from [63:0] of src1 vector:
  auto src_float = FExtractV64(FReadV64(src1), 0);

  // Store the square root result in dest[63:0]:
  auto square_root = SquareRoot64(memory, state, src_float);
  auto temp_vec = FReadV64(dst);  // initialize a destination vector
  temp_vec = FInsertV64(temp_vec, 0, square_root);

  // Write out the result and return memory state:
  FWriteV64(dst, temp_vec);  // SSE: Writes to XMM, AVX: Zero-extends XMM.
  return memory;
}

#if HAS_FEATURE_AVX
template <typename D, typename S1, typename S2>
DEF_SEM(VSQRTSD, D dst, S1 src1, S2 src2) {

  // Extract the single-precision float from [63:0] of the src2 vector:
  auto src_float = FExtractV64(FReadV64(src2), 0);

  // Initialize dest vector, while also copying src1[127:64] -> dst[127:64].
  auto temp_vec = FReadV64(src1);

  // Store the square root result in dest[63:0]:
  auto square_root = SquareRoot64(memory, state, src_float);
  temp_vec = FInsertV64(temp_vec, 0, square_root);

  // Write out the result and return memory state:
  FWriteV64(dst, temp_vec);  // SSE: Writes to XMM, AVX: Zero-extends XMM.
  return memory;
}
#endif  // HAS_FEATURE_AVX

}  // namespace

DEF_ISEL(SQRTSD_XMMsd_MEMsd) = SQRTSD<V128W, MV64>;
DEF_ISEL(SQRTSD_XMMsd_XMMsd) = SQRTSD<V128W, V128>;
IF_AVX(DEF_ISEL(VSQRTSD_XMMdq_XMMdq_MEMq) = VSQRTSD<VV128W, V128, MV64>;)
IF_AVX(DEF_ISEL(VSQRTSD_XMMdq_XMMdq_XMMq) = VSQRTSD<VV128W, V128, V128>;)
/*
4295 VSQRTSD VSQRTSD_XMMf64_MASKmskw_XMMf64_XMMf64_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MASKOP_EVEX MXCSR SIMD_SCALAR
4296 VSQRTSD VSQRTSD_XMMf64_MASKmskw_XMMf64_XMMf64_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MASKOP_EVEX MXCSR SIMD_SCALAR
4297 VSQRTSD VSQRTSD_XMMf64_MASKmskw_XMMf64_MEMf64_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: DISP8_SCALAR MASKOP_EVEX MEMORY_FAULT_SUPPRESSION MXCSR SIMD_SCALAR
*/


namespace {

template <typename D, typename S1, typename S2, typename PV>
DEF_SEM(PACKUSWB, D dst, S1 src1, S2 src2) {
  auto src1_vec = SReadV16(src1);
  auto src2_vec = SReadV16(src2);

  PV packed = {};
  const auto num_elems = NumVectorElems(packed);
  const auto half_num_elems = num_elems / 2UL;

  _Pragma("unroll") for (size_t i = 0; i < half_num_elems; ++i) {
    auto val = SExtractV16(src1_vec, i);
    auto sat = std::max<int16_t>(std::min<int16_t>(val, 255), 0);
    packed.elems[i] = static_cast<uint8_t>(sat);

    auto val2 = SExtractV16(src2_vec, i);
    auto sat2 = std::max<int16_t>(std::min<int16_t>(val2, 255), 0);
    packed.elems[half_num_elems + i] = static_cast<uint8_t>(sat2);
  }

  UWriteV8(dst, packed);
  return memory;
}

#if HAS_FEATURE_AVX

template <typename D, typename S1, typename S2, typename PV>
DEF_SEM(PACKUSWB_AVX, D dst, S1 src1, S2 src2) {
  const auto src1_vec = SReadV16(src1);
  const auto src2_vec = SReadV16(src2);
  PV packed = {};

  const auto num_elems = NumVectorElems(packed);
  const auto half_num_elems = num_elems / 2UL;
  const auto quarter_num_elems = num_elems / 4UL;

  _Pragma("unroll") for (size_t i = 0; i < quarter_num_elems; ++i) {
    auto val = SExtractV16(src1_vec, i);
    auto sat = std::max<int16_t>(std::min<int16_t>(val, 255), 0);
    packed.elems[i] = static_cast<uint8_t>(sat);

    auto val2 = SExtractV16(src1_vec, quarter_num_elems + i);
    auto sat2 = std::max<int16_t>(std::min<int16_t>(val2, 255), 0);
    packed.elems[half_num_elems + i] = static_cast<uint8_t>(sat2);

    auto val3 = SExtractV16(src2_vec, i);
    auto sat3 = std::max<int16_t>(std::min<int16_t>(val3, 255), 0);
    packed.elems[quarter_num_elems + i] = static_cast<uint8_t>(sat3);

    auto val4 = SExtractV16(src2_vec, quarter_num_elems + i);
    auto sat4 = std::max<int16_t>(std::min<int16_t>(val4, 255), 0);
    packed.elems[half_num_elems + quarter_num_elems + i] =
        static_cast<uint8_t>(sat4);
  }

  UWriteV8(dst, packed);
  return memory;
}

#endif  // HAS_FEATURE_AVX

}  // namespace

DEF_ISEL(PACKUSWB_MMXq_MEMq) = PACKUSWB<V64W, V64, MV64, uint8v8_t>;
DEF_ISEL(PACKUSWB_MMXq_MMXq) = PACKUSWB<V64W, V64, V64, uint8v8_t>;
DEF_ISEL(PACKUSWB_XMMdq_MEMdq) = PACKUSWB<V128W, V128, MV128, uint8v16_t>;
DEF_ISEL(PACKUSWB_XMMdq_XMMdq) = PACKUSWB<V128W, V128, V128, uint8v16_t>;
IF_AVX(DEF_ISEL(VPACKUSWB_XMMdq_XMMdq_MEMdq) =
           PACKUSWB<VV256W, V128, MV128, uint8v16_t>;)
IF_AVX(DEF_ISEL(VPACKUSWB_XMMdq_XMMdq_XMMdq) =
           PACKUSWB<VV256W, V128, V128, uint8v16_t>;)
IF_AVX(DEF_ISEL(VPACKUSWB_YMMqq_YMMqq_MEMqq) =
           PACKUSWB_AVX<VV256W, V256, MV256, uint8v32_t>;)
IF_AVX(DEF_ISEL(VPACKUSWB_YMMqq_YMMqq_YMMqq) =
           PACKUSWB_AVX<VV256W, V256, V256, uint8v32_t>;)

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(HADDPS, D dst, S1 src1, S2 src2) {
  auto lhs_vec = FReadV32(src1);
  auto rhs_vec = FReadV32(src2);
  auto dst_vec = FClearV32(FReadV32(dst));

  // Compute the horizontal packing
  auto vec_count = NumVectorElems(lhs_vec);
  _Pragma("unroll") for (size_t index = 0; index < vec_count; index += 2) {
    auto v1 = FExtractV32(lhs_vec, index);
    auto v2 = FExtractV32(lhs_vec, index + 1);
    auto i = UDiv(UInt32(index), UInt32(2));
    dst_vec = FInsertV32(dst_vec, i, FAdd(v1, v2));
  }
  _Pragma("unroll") for (size_t index = 0; index < NumVectorElems(rhs_vec);
                         index += 2) {
    auto v1 = FExtractV32(rhs_vec, index);
    auto v2 = FExtractV32(rhs_vec, index + 1);
    auto i = UDiv(UAdd(UInt32(index), UInt32(vec_count)), UInt32(2));
    dst_vec = FInsertV32(dst_vec, i, FAdd(v1, v2));
  }
  FWriteV32(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(HADDPD, D dst, S1 src1, S2 src2) {
  auto lhs_vec = FReadV64(src1);
  auto rhs_vec = FReadV64(src2);
  auto dst_vec = FClearV64(FReadV64(dst));

  // Compute the horizontal packing
  auto vec_count = NumVectorElems(lhs_vec);
  _Pragma("unroll") for (size_t index = 0; index < vec_count; index += 2) {
    auto v1 = FExtractV64(lhs_vec, index);
    auto v2 = FExtractV64(lhs_vec, index + 1);
    auto i = UDiv(UInt32(index), UInt32(2));
    dst_vec = FInsertV64(dst_vec, i, FAdd(v1, v2));
  }
  _Pragma("unroll") for (size_t index = 0; index < NumVectorElems(rhs_vec);
                         index += 2) {
    auto v1 = FExtractV64(rhs_vec, index);
    auto v2 = FExtractV64(rhs_vec, index + 1);
    auto i = UDiv(UAdd(UInt32(index), UInt32(vec_count)), UInt32(2));
    dst_vec = FInsertV64(dst_vec, i, FAdd(v1, v2));
  }
  FWriteV64(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(HADDPS_XMMps_XMMps) = HADDPS<V128W, V128, V128>;
DEF_ISEL(HADDPS_XMMps_MEMps) = HADDPS<V128W, V128, MV128>;
IF_AVX(DEF_ISEL(VHADDPS_XMMdq_XMMdq_XMMdq) = HADDPS<VV128W, V128, V128>;)
IF_AVX(DEF_ISEL(VHADDPS_XMMdq_XMMdq_MEMdq) = HADDPS<VV128W, V128, MV128>;)
IF_AVX(DEF_ISEL(VHADDPS_YMMqq_YMMqq_YMMqq) = HADDPS<VV256W, V256, V256>;)
IF_AVX(DEF_ISEL(VHADDPS_YMMqq_YMMqq_MEMqq) = HADDPS<VV256W, V256, MV256>;)

DEF_ISEL(HADDPD_XMMpd_XMMpd) = HADDPD<V128W, V128, V128>;
DEF_ISEL(HADDPD_XMMpd_MEMpd) = HADDPD<V128W, V128, MV128>;
IF_AVX(DEF_ISEL(VHADDPD_XMMdq_XMMdq_XMMdq) = HADDPD<VV128W, V128, V128>;)
IF_AVX(DEF_ISEL(VHADDPD_XMMdq_XMMdq_MEMdq) = HADDPD<VV128W, V128, MV128>;)
IF_AVX(DEF_ISEL(VHADDPD_YMMqq_YMMqq_YMMqq) = HADDPD<VV256W, V256, V256>;)
IF_AVX(DEF_ISEL(VHADDPD_YMMqq_YMMqq_MEMqq) = HADDPD<VV256W, V256, MV256>;)

/*
555 PACKSSDW PACKSSDW_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: HALF_WIDE_OUTPUT NOTSX
556 PACKSSDW PACKSSDW_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: HALF_WIDE_OUTPUT NOTSX
557 PACKSSDW PACKSSDW_XMMdq_MEMdq SSE SSE2 SSE2 ATTRIBUTES: HALF_WIDE_OUTPUT REQUIRES_ALIGNMENT
558 PACKSSDW PACKSSDW_XMMdq_XMMdq SSE SSE2 SSE2 ATTRIBUTES: HALF_WIDE_OUTPUT REQUIRES_ALIGNMENT
750 PACKUSDW PACKUSDW_XMMdq_MEMdq SSE SSE4 SSE4 ATTRIBUTES: HALF_WIDE_OUTPUT REQUIRES_ALIGNMENT
751 PACKUSDW PACKUSDW_XMMdq_XMMdq SSE SSE4 SSE4 ATTRIBUTES: HALF_WIDE_OUTPUT REQUIRES_ALIGNMENT
1893 PACKSSWB PACKSSWB_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: HALF_WIDE_OUTPUT NOTSX
1894 PACKSSWB PACKSSWB_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: HALF_WIDE_OUTPUT NOTSX
1895 PACKSSWB PACKSSWB_XMMdq_MEMdq SSE SSE2 SSE2 ATTRIBUTES: HALF_WIDE_OUTPUT REQUIRES_ALIGNMENT
1896 PACKSSWB PACKSSWB_XMMdq_XMMdq SSE SSE2 SSE2 ATTRIBUTES: HALF_WIDE_OUTPUT REQUIRES_ALIGNMENT
2410 VPACKSSDW VPACKSSDW_XMMdq_XMMdq_MEMdq AVX AVX AVX ATTRIBUTES:
2411 VPACKSSDW VPACKSSDW_XMMdq_XMMdq_XMMdq AVX AVX AVX ATTRIBUTES:
2412 VPACKSSDW VPACKSSDW_YMMqq_YMMqq_MEMqq AVX2 AVX2 AVX2 ATTRIBUTES:
2413 VPACKSSDW VPACKSSDW_YMMqq_YMMqq_YMMqq AVX2 AVX2 AVX2 ATTRIBUTES:

3178 VPACKUSDW VPACKUSDW_XMMdq_XMMdq_MEMdq AVX AVX AVX ATTRIBUTES:
3179 VPACKUSDW VPACKUSDW_XMMdq_XMMdq_XMMdq AVX AVX AVX ATTRIBUTES:
3180 VPACKUSDW VPACKUSDW_YMMqq_YMMqq_MEMqq AVX2 AVX2 AVX2 ATTRIBUTES:
3181 VPACKUSDW VPACKUSDW_YMMqq_YMMqq_YMMqq AVX2 AVX2 AVX2 ATTRIBUTES:
3655 VPACKSSWB VPACKSSWB_XMMdq_XMMdq_MEMdq AVX AVX AVX ATTRIBUTES:
3656 VPACKSSWB VPACKSSWB_XMMdq_XMMdq_XMMdq AVX AVX AVX ATTRIBUTES:
3657 VPACKSSWB VPACKSSWB_YMMqq_YMMqq_MEMqq AVX2 AVX2 AVX2 ATTRIBUTES:
3658 VPACKSSWB VPACKSSWB_YMMqq_YMMqq_YMMqq AVX2 AVX2 AVX2 ATTRIBUTES:
4267 VPACKSSDW VPACKSSDW_XMMi16_MASKmskw_XMMi32_XMMi32_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: MASKOP_EVEX
4268 VPACKSSDW VPACKSSDW_XMMi16_MASKmskw_XMMi32_MEMi32_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX
4269 VPACKSSDW VPACKSSDW_YMMi16_MASKmskw_YMMi32_YMMi32_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: MASKOP_EVEX
4270 VPACKSSDW VPACKSSDW_YMMi16_MASKmskw_YMMi32_MEMi32_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX
4271 VPACKSSDW VPACKSSDW_ZMMi16_MASKmskw_ZMMi32_ZMMi32_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: MASKOP_EVEX
4272 VPACKSSDW VPACKSSDW_ZMMi16_MASKmskw_ZMMi32_MEMi32_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX
4796 VPACKUSWB VPACKUSWB_XMMu8_MASKmskw_XMMu16_XMMu16_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: MASKOP_EVEX
4797 VPACKUSWB VPACKUSWB_XMMu8_MASKmskw_XMMu16_MEMu16_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX
4798 VPACKUSWB VPACKUSWB_YMMu8_MASKmskw_YMMu16_YMMu16_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: MASKOP_EVEX
4799 VPACKUSWB VPACKUSWB_YMMu8_MASKmskw_YMMu16_MEMu16_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX
4800 VPACKUSWB VPACKUSWB_ZMMu8_MASKmskw_ZMMu16_ZMMu16_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: MASKOP_EVEX
4801 VPACKUSWB VPACKUSWB_ZMMu8_MASKmskw_ZMMu16_MEMu16_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX
5536 VPACKUSDW VPACKUSDW_XMMu16_MASKmskw_XMMu32_XMMu32_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: MASKOP_EVEX
5537 VPACKUSDW VPACKUSDW_XMMu16_MASKmskw_XMMu32_MEMu32_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX
5538 VPACKUSDW VPACKUSDW_YMMu16_MASKmskw_YMMu32_YMMu32_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: MASKOP_EVEX
5539 VPACKUSDW VPACKUSDW_YMMu16_MASKmskw_YMMu32_MEMu32_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX
5540 VPACKUSDW VPACKUSDW_ZMMu16_MASKmskw_ZMMu32_ZMMu32_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: MASKOP_EVEX
5541 VPACKUSDW VPACKUSDW_ZMMu16_MASKmskw_ZMMu32_MEMu32_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX
6430 VPACKSSWB VPACKSSWB_XMMi8_MASKmskw_XMMi16_XMMi16_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: MASKOP_EVEX
6431 VPACKSSWB VPACKSSWB_XMMi8_MASKmskw_XMMi16_MEMi16_AVX512 AVX512 AVX512EVEX AVX512BW_128 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX
6432 VPACKSSWB VPACKSSWB_YMMi8_MASKmskw_YMMi16_YMMi16_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: MASKOP_EVEX
6433 VPACKSSWB VPACKSSWB_YMMi8_MASKmskw_YMMi16_MEMi16_AVX512 AVX512 AVX512EVEX AVX512BW_256 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX
6434 VPACKSSWB VPACKSSWB_ZMMi8_MASKmskw_ZMMi16_ZMMi16_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: MASKOP_EVEX
6435 VPACKSSWB VPACKSSWB_ZMMi8_MASKmskw_ZMMi16_MEMi16_AVX512 AVX512 AVX512EVEX AVX512BW_512 ATTRIBUTES: DISP8_FULLMEM MASKOP_EVEX
 */


namespace {

DEF_SEM(LDMXCSR, M32 src) {
  auto &csr = state.x87.fxsave.mxcsr;
  csr.flat = Read(src);

  int rounding_mode = FE_TONEAREST;

  if (!csr.rp && !csr.rn) {
    rounding_mode = FE_TONEAREST;
  } else if (!csr.rp && csr.rn) {
    rounding_mode = FE_DOWNWARD;
  } else if (csr.rp && !csr.rn) {
    rounding_mode = FE_UPWARD;
  } else {
    rounding_mode = FE_TOWARDZERO;
  }
  fesetround(rounding_mode);

  // TODO: set FPU precision based on MXCSR precision flag (csr.pe)

  return memory;
}

DEF_SEM(STMXCSR, M32W dst) {
  auto &csr = state.x87.fxsave.mxcsr;

  // TODO: store the current FPU precision control:
  csr.pe = 0;

  // Store the current FPU rounding mode:
  switch (fegetround()) {
    default:
    case FE_TONEAREST:
      csr.rp = 0;
      csr.rn = 0;
      break;
    case FE_DOWNWARD:
      csr.rp = 0;
      csr.rn = 1;
      break;
    case FE_UPWARD:
      csr.rp = 1;
      csr.rn = 0;
      break;
    case FE_TOWARDZERO:
      csr.rp = 1;
      csr.rn = 1;
      break;
  }

  Write(dst, csr.flat);

  return memory;
}

}  // namespace

DEF_ISEL(LDMXCSR_MEMd) = LDMXCSR;
DEF_ISEL(STMXCSR_MEMd) = STMXCSR;
IF_AVX(DEF_ISEL(VLDMXCSR_MEMd) = LDMXCSR;)
IF_AVX(DEF_ISEL(VSTMXCSR_MEMd) = STMXCSR;)
