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

template <typename D, typename S1, typename S2>
DEF_SEM(BLENDPS, D dst, S1 src1, S2 src2, I8 src3) {
  auto dst_vec = UReadV32(src1);
  auto src2_vec = UReadV32(src2);
  auto imm = Read(src3);
  auto num_groups = NumVectorElems(dst_vec);

  _Pragma("unroll") for (std::size_t i = 0; i < num_groups; ++i) {
    auto bit = UAnd8(UShr8(imm, TruncTo<uint8_t>(i)), 1_u8);
    auto val = Select(bit != 0_u8, UExtractV32(src2_vec, i),
                      UExtractV32(dst_vec, i));
    dst_vec = UInsertV32(dst_vec, i, val);
  }

  UWriteV32(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(BLENDPD, D dst, S1 src1, S2 src2, I8 src3) {
  auto dst_vec = UReadV64(src1);
  auto src2_vec = UReadV64(src2);
  auto imm = Read(src3);
  auto num_groups = NumVectorElems(dst_vec);

  _Pragma("unroll") for (std::size_t i = 0; i < num_groups; ++i) {
    auto bit = UAnd8(UShr8(imm, TruncTo<uint8_t>(i)), 1_u8);
    auto val = Select(bit != 0_u8, UExtractV64(src2_vec, i),
                      UExtractV64(dst_vec, i));
    dst_vec = UInsertV64(dst_vec, i, val);
  }

  UWriteV64(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(BLENDVPS, D dst, S1 src1, S2 src2) {
  auto dst_vec = UReadV32(src1);
  auto src2_vec = UReadV32(src2);
  auto mask_vec = state.vec[0].xmm.dwords;
  auto num_groups = NumVectorElems(dst_vec);

  _Pragma("unroll") for (std::size_t i = 0; i < num_groups; ++i) {
    auto mask = mask_vec.elems[i];
    auto val = Select(UShr(mask, 31_u32) != 0_u32, UExtractV32(src2_vec, i),
                      UExtractV32(dst_vec, i));
    dst_vec = UInsertV32(dst_vec, i, val);
  }

  UWriteV32(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(BLENDVPD, D dst, S1 src1, S2 src2) {
  auto dst_vec = UReadV64(src1);
  auto src2_vec = UReadV64(src2);
  auto mask_vec = state.vec[0].xmm.qwords;
  auto num_groups = NumVectorElems(dst_vec);

  _Pragma("unroll") for (std::size_t i = 0; i < num_groups; ++i) {
    auto mask = mask_vec.elems[i];
    auto val = Select(UShr(mask, 63_u64) != 0_u64, UExtractV64(src2_vec, i),
                      UExtractV64(dst_vec, i));
    dst_vec = UInsertV64(dst_vec, i, val);
  }

  UWriteV64(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(BLENDPS_XMMdq_XMMdq_IMMb) = BLENDPS<V128W, V128, V128>;
DEF_ISEL(BLENDPS_XMMdq_MEMdq_IMMb) = BLENDPS<V128W, V128, MV128>;

DEF_ISEL(BLENDPD_XMMdq_XMMdq_IMMb) = BLENDPD<V128W, V128, V128>;
DEF_ISEL(BLENDPD_XMMdq_MEMdq_IMMb) = BLENDPD<V128W, V128, MV128>;

DEF_ISEL(BLENDVPS_XMMdq_XMMdq) = BLENDVPS<V128W, V128, V128>;
DEF_ISEL(BLENDVPS_XMMdq_MEMdq) = BLENDVPS<V128W, V128, MV128>;

DEF_ISEL(BLENDVPD_XMMdq_XMMdq) = BLENDVPD<V128W, V128, V128>;
DEF_ISEL(BLENDVPD_XMMdq_MEMdq) = BLENDVPD<V128W, V128, MV128>;

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(INSERTPS, D dst, S1 src1, S2 src2, I8 src3) {
  auto dst_vec = UReadV32(src1);
  auto src2_vec = UReadV32(src2);
  auto imm = Read(src3);
  auto src_index = URem(UShr8(imm, 6_u8), UInt8(NumVectorElems(src2_vec)));
  auto dst_index = UAnd8(UShr8(imm, 4_u8), 3_u8);
  auto val = UExtractV32(src2_vec, src_index);

  dst_vec = UInsertV32(dst_vec, dst_index, val);

  auto num_groups = NumVectorElems(dst_vec);
  _Pragma("unroll") for (std::size_t i = 0; i < num_groups; ++i) {
    auto zero_bit = UAnd8(UShr8(imm, TruncTo<uint8_t>(i)), 1_u8);
    auto lane = Select(zero_bit != 0_u8, 0_u32, UExtractV32(dst_vec, i));
    dst_vec = UInsertV32(dst_vec, i, lane);
  }

  UWriteV32(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(EXTRACTPS_GPR32d_XMMdq_IMMb) = PEXTRD<R32W, V128>;
DEF_ISEL(EXTRACTPS_MEMd_XMMdq_IMMb) = PEXTRD<M32W, V128>;

DEF_ISEL(INSERTPS_XMMps_XMMps_IMMb) = INSERTPS<V128W, V128, V128>;
DEF_ISEL(INSERTPS_XMMps_MEMd_IMMb) = INSERTPS<V128W, V128, MV32>;

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

template <bool kUseFullPredicate, typename D, typename S1, typename S2>
DEF_SEM(CMPSS, D dst, S1 src1, S2 src2, I8 src3) {
  auto src1_vec = FReadV32(src1);
  auto src2_vec = FReadV32(src2);
  auto dst_vec = UClearV32(UReadV32(dst));
  auto op = Read(src3);
  if (!kUseFullPredicate) {
    op = UAnd8(op, 7_u8);
  }
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

template <bool kUseFullPredicate, typename D, typename S1, typename S2>
DEF_SEM(CMPSD, D dst, S1 src1, S2 src2, I8 src3) {
  auto src1_vec = FReadV64(src1);
  auto src2_vec = FReadV64(src2);
  auto dst_vec = UClearV64(UReadV64(dst));
  auto op = Read(src3);
  if (!kUseFullPredicate) {
    op = UAnd8(op, 7_u8);
  }
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

DEF_ISEL(CMPSS_XMMss_MEMss_IMMb) = CMPSS<false, V128W, V128, MV32>;
DEF_ISEL(CMPSS_XMMss_XMMss_IMMb) = CMPSS<false, V128W, V128, V128>;

#if HAS_FEATURE_AVX
DEF_ISEL(VCMPSS_XMMdq_XMMdq_MEMd_IMMb) = CMPSS<true, VV128W, V128, MV32>;
DEF_ISEL(VCMPSS_XMMdq_XMMdq_XMMd_IMMb) = CMPSS<true, VV128W, V128, V128>;
#endif  // HAS_FEATURE_AVX

DEF_ISEL(CMPSD_XMM_XMMsd_MEMsd_IMMb) = CMPSD<false, V128W, V128, MV64>;
DEF_ISEL(CMPSD_XMM_XMMsd_XMMsd_IMMb) = CMPSD<false, V128W, V128, V128>;

#if HAS_FEATURE_AVX
DEF_ISEL(VCMPSD_XMMdq_XMMdq_MEMq_IMMb) = CMPSD<true, VV128W, V128, MV64>;
DEF_ISEL(VCMPSD_XMMdq_XMMdq_XMMq_IMMb) = CMPSD<true, VV128W, V128, V128>;
#endif  // HAS_FEATURE_AVX

namespace {
template <bool kUseFullPredicate, typename D, typename S1, typename S2>
DEF_SEM(CMPPS, D dst, S1 src1, S2 src2, I8 src3) {
  auto src1_vec = FReadV32(src1);
  auto src2_vec = FReadV32(src2);
  auto dst_vec = UClearV32(UReadV32(dst));
  auto op = Read(src3);
  if (!kUseFullPredicate) {
    op = UAnd8(op, 7_u8);
  }
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

template <bool kUseFullPredicate, typename D, typename S1, typename S2>
DEF_SEM(CMPPD, D dst, S1 src1, S2 src2, I8 src3) {
  auto src1_vec = FReadV64(src1);
  auto src2_vec = FReadV64(src2);
  auto dst_vec = UClearV64(UReadV64(dst));
  auto op = Read(src3);
  if (!kUseFullPredicate) {
    op = UAnd8(op, 7_u8);
  }
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

DEF_ISEL(CMPPS_XMMps_MEMps_IMMb) = CMPPS<false, V128W, V128, MV128>;
DEF_ISEL(CMPPS_XMMps_XMMps_IMMb) = CMPPS<false, V128W, V128, V128>;

#if HAS_FEATURE_AVX
DEF_ISEL(VCMPPS_XMMdq_XMMdq_MEMdq_IMMb) = CMPPS<true, VV128W, V128, MV128>;
DEF_ISEL(VCMPPS_XMMdq_XMMdq_XMMdq_IMMb) = CMPPS<true, VV128W, V128, V128>;
DEF_ISEL(VCMPPS_YMMqq_YMMqq_MEMqq_IMMb) = CMPPS<true, VV256W, V256, MV256>;
DEF_ISEL(VCMPPS_YMMqq_YMMqq_YMMqq_IMMb) = CMPPS<true, VV256W, V256, V256>;
#endif  // HAS_FEATURE_AVX

DEF_ISEL(CMPPD_XMMpd_MEMpd_IMMb) = CMPPD<false, V128W, V128, MV128>;
DEF_ISEL(CMPPD_XMMpd_XMMpd_IMMb) = CMPPD<false, V128W, V128, V128>;

#if HAS_FEATURE_AVX
DEF_ISEL(VCMPPD_XMMdq_XMMdq_MEMdq_IMMb) = CMPPD<true, VV128W, V128, MV128>;
DEF_ISEL(VCMPPD_XMMdq_XMMdq_XMMdq_IMMb) = CMPPD<true, VV128W, V128, V128>;
DEF_ISEL(VCMPPD_YMMqq_YMMqq_MEMqq_IMMb) = CMPPD<true, VV256W, V256, MV256>;
DEF_ISEL(VCMPPD_YMMqq_YMMqq_YMMqq_IMMb) = CMPPD<true, VV256W, V256, V256>;
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

// https://godbolt.org/z/fa4vGfoxd
template <size_t x, size_t y>
class BitMatrix {
 public:
  ALWAYS_INLINE bool Test(size_t i, size_t j) const {
    size_t pos = (x * i) + j;
    return (data[pos / 8] >> (pos % 8)) & 1;
  }

  ALWAYS_INLINE void Set(size_t i, size_t j, bool val) {
    size_t pos = (x * i) + j;
    if (val) {
      data[pos / 8] |= (uint8_t(1) << (pos % 8));
    } else {
      data[pos / 8] &= ~(uint8_t(1) << (pos % 8));
    }
  }

 private:
  uint8_t data[(x * y + 7) / 8] = {};
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

template <typename D, typename S1, typename S2>
DEF_SEM(MINPD, D dst, S1 src1, S2 src2) {
  auto dest_vec = FReadV64(src1);
  auto src2_vec = FReadV64(src2);

  auto vec_count = NumVectorElems(src2_vec);
  _Pragma("unroll") for (std::size_t i = 0; i < vec_count; i++) {
    auto v1 = FExtractV64(dest_vec, i);
    auto v2 = FExtractV64(src2_vec, i);

    auto min = v1;

    // If either float is a NaN (SNaN or QNaN):
    if (std::isunordered(v1, v2)) {
      min = v2;

      // or if both floats are 0.0:
    } else if ((v1 == 0.0) && (v2 == 0.0)) {
      min = v2;

      // or if src2 is less than src1:
    } else if (v2 < v1) {
      min = v2;
    }

    dest_vec = FInsertV64(dest_vec, i, min);
  }
  FWriteV64(dst, dest_vec);  // SSE: Writes to XMM, AVX: Zero-extends XMM.
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(MAXPD, D dst, S1 src1, S2 src2) {
  auto dest_vec = FReadV64(src1);
  auto src2_vec = FReadV64(src2);

  auto vec_count = NumVectorElems(src2_vec);
  _Pragma("unroll") for (std::size_t i = 0; i < vec_count; i++) {
    auto v1 = FExtractV64(dest_vec, i);
    auto v2 = FExtractV64(src2_vec, i);

    auto max = v1;

    // If either float is a NaN (SNaN or QNaN):
    if (std::isunordered(v1, v2)) {
      max = v2;

      // or if both floats are 0.0:
    } else if ((v1 == 0.0) && (v2 == 0.0)) {
      max = v2;

      // or if src2 is greater than src1:
    } else if (v2 > v1) {
      max = v2;
    }

    dest_vec = FInsertV64(dest_vec, i, max);
  }
  FWriteV64(dst, dest_vec);  // SSE: Writes to XMM, AVX: Zero-extends XMM.
  return memory;
}

}  // namespace

DEF_ISEL(MINPS_XMMps_MEMps) = MINPS<V128W, V128, MV128>;
DEF_ISEL(MINPS_XMMps_XMMps) = MINPS<V128W, V128, V128>;

DEF_ISEL(MAXPS_XMMps_XMMps) = MAXPS<V128W, V128, V128>;
DEF_ISEL(MAXPS_XMMps_MEMps) = MAXPS<V128W, V128, MV128>;

DEF_ISEL(MINPD_XMMpd_MEMpd) = MINPD<V128W, V128, MV128>;
DEF_ISEL(MINPD_XMMpd_XMMpd) = MINPD<V128W, V128, V128>;

DEF_ISEL(MAXPD_XMMpd_MEMpd) = MAXPD<V128W, V128, MV128>;
DEF_ISEL(MAXPD_XMMpd_XMMpd) = MAXPD<V128W, V128, V128>;

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

#define MAKE_MOVDDUP(num_src_elements) \
  template <typename D, typename S1> \
  DEF_SEM(MOVDDUP_##num_src_elements, D dst, S1 src) { \
\
    /* Treat src as a vector of QWORD (64-bit) floats, even if it's just one element:*/ \
    auto src_vec = FReadV64(src); \
    auto tmp_vec = FClearV64(FReadV64(dst)); \
\
    /* "Move and duplicate" QWORD src[63:0] into dest[63:0] and into dest[127:64]:*/ \
    _Pragma("unroll") for (auto idx = 0u; idx < num_src_elements * 2; \
                           idx += 2) { \
      auto src_float = FExtractV64(src_vec, idx); \
      tmp_vec = FInsertV64(tmp_vec, idx, src_float); \
      tmp_vec = FInsertV64(tmp_vec, idx + 1, src_float); \
    } \
    /* SSE: Writes to XMM (dest[MAXVL-1:127] unmodified). AVX: Zero-extends XMM.*/ \
    FWriteV64(dst, tmp_vec); \
    return memory; \
  }

// for SSE and VEX.128
MAKE_MOVDDUP(1)
// for VEX.256
MAKE_MOVDDUP(2)

#undef MAKE_MOVDDUP

}  // namespace

DEF_ISEL(MOVDDUP_XMMdq_MEMq) = MOVDDUP_1<V128W, MV64>;
DEF_ISEL(MOVDDUP_XMMdq_XMMq) = MOVDDUP_1<V128W, V128>;
IF_AVX(DEF_ISEL(VMOVDDUP_XMMdq_MEMq) = MOVDDUP_1<VV128W, MV64>;)
IF_AVX(DEF_ISEL(VMOVDDUP_XMMdq_XMMq) = MOVDDUP_1<VV128W, V128>;)
IF_AVX(DEF_ISEL(VMOVDDUP_YMMqq_MEMqq) = MOVDDUP_2<VV256W, MV128>;)
IF_AVX(DEF_ISEL(VMOVDDUP_YMMqq_YMMqq) = MOVDDUP_2<VV256W, V256>;)
/*
4070 VMOVDDUP VMOVDDUP_ZMMf64_MASKmskw_ZMMf64_AVX512 DATAXFER AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
4071 VMOVDDUP VMOVDDUP_ZMMf64_MASKmskw_MEMf64_AVX512 DATAXFER AVX512EVEX AVX512F_512 ATTRIBUTES: DISP8_MOVDDUP MASKOP_EVEX
4072 VMOVDDUP VMOVDDUP_XMMf64_MASKmskw_XMMf64_AVX512 DATAXFER AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
4073 VMOVDDUP VMOVDDUP_XMMf64_MASKmskw_MEMf64_AVX512 DATAXFER AVX512EVEX AVX512F_128 ATTRIBUTES: DISP8_MOVDDUP MASKOP_EVEX
4074 VMOVDDUP VMOVDDUP_YMMf64_MASKmskw_YMMf64_AVX512 DATAXFER AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
4075 VMOVDDUP VMOVDDUP_YMMf64_MASKmskw_MEMf64_AVX512 DATAXFER AVX512EVEX AVX512F_256 ATTRIBUTES: DISP8_MOVDDUP MASKOP_EVEX
*/

namespace {

#define MAKE_MOVSxDUP(name, src_idx) \
  template <typename D, typename S1> \
  DEF_SEM(MOVS##name##DUP, D dst, S1 src) { \
    auto src_vec = FReadV32(src); \
    auto dst_vec = FClearV32(FReadV32(dst)); \
    auto vector_count = NumVectorElems(src_vec); \
    _Pragma("unroll") for (auto idx = 0u; idx < vector_count; idx += 2) { \
      auto src_float = FExtractV32(src_vec, idx + src_idx); \
      dst_vec = FInsertV32(dst_vec, idx, src_float); \
      dst_vec = FInsertV32(dst_vec, idx + 1, src_float); \
    } \
    FWriteV32(dst, dst_vec); \
    return memory; \
  }

MAKE_MOVSxDUP(L, 0u) MAKE_MOVSxDUP(H, 1u)

#undef MAKE_MOVDDUP

}  // namespace

DEF_ISEL(MOVSLDUP_XMMps_MEMps) = MOVSLDUP<V128W, MV128>;
DEF_ISEL(MOVSLDUP_XMMps_XMMps) = MOVSLDUP<V128W, V128>;
IF_AVX(DEF_ISEL(VMOVSLDUP_XMMdq_MEMdq) = MOVSLDUP<VV128W, MV128>;)
IF_AVX(DEF_ISEL(VMOVSLDUP_XMMdq_XMMdq) = MOVSLDUP<VV128W, V128>;)
IF_AVX(DEF_ISEL(VMOVSLDUP_YMMqq_MEMqq) = MOVSLDUP<VV256W, MV256>;)
IF_AVX(DEF_ISEL(VMOVSLDUP_YMMqq_YMMqq) = MOVSLDUP<VV256W, V256>;)

DEF_ISEL(MOVSHDUP_XMMps_MEMps) = MOVSHDUP<V128W, MV128>;
DEF_ISEL(MOVSHDUP_XMMps_XMMps) = MOVSHDUP<V128W, V128>;
IF_AVX(DEF_ISEL(VMOVSHDUP_XMMdq_MEMdq) = MOVSHDUP<VV128W, MV128>;)
IF_AVX(DEF_ISEL(VMOVSHDUP_XMMdq_XMMdq) = MOVSHDUP<VV128W, V128>;)
IF_AVX(DEF_ISEL(VMOVSHDUP_YMMqq_MEMqq) = MOVSHDUP<VV256W, MV256>;)
IF_AVX(DEF_ISEL(VMOVSHDUP_YMMqq_YMMqq) = MOVSHDUP<VV256W, V256>;)

namespace {

struct ApproxFpPair {
  uint32_t input;
  uint32_t output;
};

static constexpr ApproxFpPair kApproxRcp32Table[] = {
    {0x00000000U, 0x7f800000U},
    {0x00000001U, 0x7f800000U},
    {0x00000002U, 0x7f800000U},
    {0x00000004U, 0x7f800000U},
    {0x00000008U, 0x7f800000U},
    {0x00000009U, 0x7f800000U},
    {0x00000010U, 0x7f800000U},
    {0x00000020U, 0x7f800000U},
    {0x00000021U, 0x7f800000U},
    {0x0000002cU, 0x7f800000U},
    {0x00000040U, 0x7f800000U},
    {0x00000050U, 0x7f800000U},
    {0x00000061U, 0x7f800000U},
    {0x00000080U, 0x7f800000U},
    {0x00000088U, 0x7f800000U},
    {0x000000b0U, 0x7f800000U},
    {0x000000c0U, 0x7f800000U},
    {0x00000100U, 0x7f800000U},
    {0x00000101U, 0x7f800000U},
    {0x00000120U, 0x7f800000U},
    {0x00000184U, 0x7f800000U},
    {0x00000200U, 0x7f800000U},
    {0x00000240U, 0x7f800000U},
    {0x00000248U, 0x7f800000U},
    {0x00000280U, 0x7f800000U},
    {0x0000028dU, 0x7f800000U},
    {0x00000300U, 0x7f800000U},
    {0x000003a0U, 0x7f800000U},
    {0x00000400U, 0x7f800000U},
    {0x00000402U, 0x7f800000U},
    {0x00000612U, 0x7f800000U},
    {0x00000800U, 0x7f800000U},
    {0x00000880U, 0x7f800000U},
    {0x00000900U, 0x7f800000U},
    {0x00001000U, 0x7f800000U},
    {0x00001004U, 0x7f800000U},
    {0x00001030U, 0x7f800000U},
    {0x00002000U, 0x7f800000U},
    {0x00002001U, 0x7f800000U},
    {0x00002004U, 0x7f800000U},
    {0x00002080U, 0x7f800000U},
    {0x000020a0U, 0x7f800000U},
    {0x00002705U, 0x7f800000U},
    {0x00002804U, 0x7f800000U},
    {0x00004000U, 0x7f800000U},
    {0x00004004U, 0x7f800000U},
    {0x00004204U, 0x7f800000U},
    {0x00004800U, 0x7f800000U},
    {0x00004a80U, 0x7f800000U},
    {0x00005000U, 0x7f800000U},
    {0x00008000U, 0x7f800000U},
    {0x00008004U, 0x7f800000U},
    {0x00008044U, 0x7f800000U},
    {0x00008400U, 0x7f800000U},
    {0x00008800U, 0x7f800000U},
    {0x00008802U, 0x7f800000U},
    {0x00009800U, 0x7f800000U},
    {0x0000c000U, 0x7f800000U},
    {0x00010000U, 0x7f800000U},
    {0x00012010U, 0x7f800000U},
    {0x00012290U, 0x7f800000U},
    {0x00014008U, 0x7f800000U},
    {0x00016081U, 0x7f800000U},
    {0x00020000U, 0x7f800000U},
    {0x00020002U, 0x7f800000U},
    {0x00020010U, 0x7f800000U},
    {0x00020400U, 0x7f800000U},
    {0x00020820U, 0x7f800000U},
    {0x00020880U, 0x7f800000U},
    {0x00020c02U, 0x7f800000U},
    {0x00022044U, 0x7f800000U},
    {0x00024008U, 0x7f800000U},
    {0x00040000U, 0x7f800000U},
    {0x00040004U, 0x7f800000U},
    {0x00040100U, 0x7f800000U},
    {0x00040102U, 0x7f800000U},
    {0x00044420U, 0x7f800000U},
    {0x00050000U, 0x7f800000U},
    {0x00051020U, 0x7f800000U},
    {0x00060802U, 0x7f800000U},
    {0x00061040U, 0x7f800000U},
    {0x00080000U, 0x7f800000U},
    {0x00080040U, 0x7f800000U},
    {0x00080200U, 0x7f800000U},
    {0x00080600U, 0x7f800000U},
    {0x00080802U, 0x7f800000U},
    {0x00090040U, 0x7f800000U},
    {0x00090900U, 0x7f800000U},
    {0x000a0000U, 0x7f800000U},
    {0x000a0016U, 0x7f800000U},
    {0x000a0a70U, 0x7f800000U},
    {0x000b0181U, 0x7f800000U},
    {0x000c0240U, 0x7f800000U},
    {0x00100000U, 0x7f800000U},
    {0x00100008U, 0x7f800000U},
    {0x00100020U, 0x7f800000U},
    {0x00100980U, 0x7f800000U},
    {0x0010aa00U, 0x7f800000U},
    {0x00110080U, 0x7f800000U},
    {0x00161200U, 0x7f800000U},
    {0x00180000U, 0x7f800000U},
    {0x00200000U, 0x7f800000U},
    {0x00200020U, 0x7f800000U},
    {0x00200280U, 0x7f800000U},
    {0x00200500U, 0x7f800000U},
    {0x00202000U, 0x7f800000U},
    {0x00202042U, 0x7f800000U},
    {0x00208014U, 0x7f800000U},
    {0x00208040U, 0x7f800000U},
    {0x0020b008U, 0x7f800000U},
    {0x0020cc61U, 0x7f800000U},
    {0x00221800U, 0x7f800000U},
    {0x00242136U, 0x7f800000U},
    {0x002c0ca2U, 0x7f800000U},
    {0x00300146U, 0x7f800000U},
    {0x00320000U, 0x7f800000U},
    {0x00400000U, 0x7f800000U},
    {0x00400001U, 0x7f800000U},
    {0x00400102U, 0x7f800000U},
    {0x00400800U, 0x7f800000U},
    {0x00402004U, 0x7f800000U},
    {0x004026a5U, 0x7f800000U},
    {0x00404250U, 0x7f800000U},
    {0x004209d0U, 0x7f800000U},
    {0x00440100U, 0x7f800000U},
    {0x00442400U, 0x7f800000U},
    {0x00517006U, 0x7f800000U},
    {0x00620800U, 0x7f800000U},
    {0x00718a02U, 0x7f800000U},
    {0x00800000U, 0x7e7ff000U},
    {0x00800002U, 0x7e7ff000U},
    {0x00800004U, 0x7e7ff000U},
    {0x00800008U, 0x7e7ff000U},
    {0x00800040U, 0x7e7ff000U},
    {0x00800088U, 0x7e7ff000U},
    {0x00800100U, 0x7e7ff000U},
    {0x00800400U, 0x7e7ff000U},
    {0x00802000U, 0x7e7fb800U},
    {0x00804000U, 0x7e7f7800U},
    {0x00808001U, 0x7e7ef000U},
    {0x00810010U, 0x7e7df800U},
    {0x00810900U, 0x7e7de800U},
    {0x00811848U, 0x7e7dd000U},
    {0x00820000U, 0x7e7c0800U},
    {0x00822000U, 0x7e7bd000U},
    {0x00840000U, 0x7e783800U},
    {0x00840020U, 0x7e783800U},
    {0x00841181U, 0x7e782000U},
    {0x00885084U, 0x7e706000U},
    {0x0088d889U, 0x7e6f7000U},
    {0x008a49c0U, 0x7e6cf000U},
    {0x008a6640U, 0x7e6cc800U},
    {0x00901080U, 0x7e636800U},
    {0x00908400U, 0x7e62b800U},
    {0x00a04c18U, 0x7e4c6800U},
    {0x00a42080U, 0x7e47a800U},
    {0x00c00801U, 0x7e2aa000U},
    {0x00c80000U, 0x7e23d000U},
    {0x00c808e7U, 0x7e23c800U},
    {0x00c87008U, 0x7e237800U},
    {0x00e0a889U, 0x7e11d800U},
    {0x00f88101U, 0x7e03d800U},
    {0x00fb8200U, 0x7e024800U},
    {0x01000000U, 0x7dfff000U},
    {0x01000001U, 0x7dfff000U},
    {0x01000002U, 0x7dfff000U},
    {0x0100000aU, 0x7dfff000U},
    {0x01000044U, 0x7dfff000U},
    {0x01000100U, 0x7dfff000U},
    {0x01000246U, 0x7dfff000U},
    {0x01000400U, 0x7dfff000U},
    {0x01000504U, 0x7dfff000U},
    {0x01000840U, 0x7dffe000U},
    {0x01000a00U, 0x7dffe000U},
    {0x01000a30U, 0x7dffe000U},
    {0x01001100U, 0x7dffd800U},
    {0x01002000U, 0x7dffb800U},
    {0x01008000U, 0x7dfef000U},
    {0x0100a084U, 0x7dfeb800U},
    {0x01010810U, 0x7dfde800U},
    {0x01011114U, 0x7dfde000U},
    {0x01012100U, 0x7dfdc000U},
    {0x01018040U, 0x7dfcf800U},
    {0x01020050U, 0x7dfc0800U},
    {0x0103b800U, 0x7df8c000U},
    {0x01040440U, 0x7df83800U},
    {0x010800e8U, 0x7df0e000U},
    {0x01080100U, 0x7df0e000U},
    {0x0108c03cU, 0x7def9800U},
    {0x010c0134U, 0x7dea0800U},
    {0x01100801U, 0x7de37800U},
    {0x01120440U, 0x7de06800U},
    {0x0117ae7fU, 0x7dd81000U},
    {0x01200202U, 0x7dccc000U},
    {0x01202200U, 0x7dcca000U},
    {0x01394122U, 0x7db0e000U},
    {0x01400040U, 0x7daaa800U},
    {0x01410000U, 0x7da9c000U},
    {0x014226d1U, 0x7da8d000U},
    {0x014a1040U, 0x7da23000U},
    {0x01800010U, 0x7d7ff000U},
    {0x018c2942U, 0x7d69c800U},
    {0x01a00024U, 0x7d4cc000U},
    {0x02000000U, 0x7cfff000U},
    {0x02000007U, 0x7cfff000U},
    {0x02000008U, 0x7cfff000U},
    {0x02000020U, 0x7cfff000U},
    {0x02000080U, 0x7cfff000U},
    {0x02000101U, 0x7cfff000U},
    {0x02000d03U, 0x7cffe000U},
    {0x02002000U, 0x7cffb800U},
    {0x02002040U, 0x7cffb800U},
    {0x02004080U, 0x7cff7800U},
    {0x02005080U, 0x7cff6000U},
    {0x0200c227U, 0x7cfe7800U},
    {0x02010000U, 0x7cfdf800U},
    {0x0202010cU, 0x7cfc0800U},
    {0x020208c1U, 0x7cfbf800U},
    {0x02040004U, 0x7cf83800U},
    {0x02040400U, 0x7cf83800U},
    {0x02040824U, 0x7cf82800U},
    {0x02042100U, 0x7cf80000U},
    {0x02042200U, 0x7cf80000U},
    {0x02059070U, 0x7cf55800U},
    {0x02060103U, 0x7cf48800U},
    {0x02080a00U, 0x7cf0d800U},
    {0x02084400U, 0x7cf07800U},
    {0x0208c0cdU, 0x7cef9800U},
    {0x02095d11U, 0x7cee9000U},
    {0x02101080U, 0x7ce36800U},
    {0x02108000U, 0x7ce2b800U},
    {0x02200202U, 0x7cccc000U},
    {0x02200c20U, 0x7cccb800U},
    {0x02250000U, 0x7cc69000U},
    {0x02298148U, 0x7cc15000U},
    {0x02400000U, 0x7caaa800U},
    {0x02401400U, 0x7caa9800U},
    {0x02441001U, 0x7ca72000U},
    {0x024980fcU, 0x7ca29800U},
    {0x02504d80U, 0x7c9d5000U},
    {0x02564000U, 0x7c98f000U},
    {0x02703e02U, 0x7c886800U},
    {0x02800000U, 0x7c7ff000U},
    {0x0280882aU, 0x7c7ee000U},
    {0x02856828U, 0x7c759800U},
    {0x02880042U, 0x7c70e000U},
    {0x028ace01U, 0x7c6c1800U},
    {0x0290395eU, 0x7c633000U},
    {0x02910e52U, 0x7c61e800U},
    {0x02a00a8cU, 0x7c4cb800U},
    {0x02e98509U, 0x7c0c5000U},
    {0x03001294U, 0x7bffd800U},
    {0x03004000U, 0x7bff7800U},
    {0x03008800U, 0x7bfee000U},
    {0x03049100U, 0x7bf73000U},
    {0x030620f4U, 0x7bf45000U},
    {0x03208554U, 0x7bcc2000U},
    {0x03442760U, 0x7ba71800U},
    {0x04000000U, 0x7afff000U},
    {0x04000004U, 0x7afff000U},
    {0x04000008U, 0x7afff000U},
    {0x04000010U, 0x7afff000U},
    {0x040000d0U, 0x7afff000U},
    {0x04000100U, 0x7afff000U},
    {0x04000140U, 0x7afff000U},
    {0x04000200U, 0x7afff000U},
    {0x04000208U, 0x7afff000U},
    {0x04000d02U, 0x7affe000U},
    {0x04001000U, 0x7affd800U},
    {0x04002020U, 0x7affb800U},
    {0x040020c0U, 0x7affb800U},
    {0x04010618U, 0x7afdf800U},
    {0x04020000U, 0x7afc0800U},
    {0x04022800U, 0x7afbc000U},
    {0x04040000U, 0x7af83800U},
    {0x040400a8U, 0x7af83800U},
    {0x04040800U, 0x7af82800U},
    {0x04100200U, 0x7ae38000U},
    {0x04104c08U, 0x7ae31800U},
    {0x04202010U, 0x7acca000U},
    {0x0420a000U, 0x7acc0000U},
    {0x0421c830U, 0x7aca8800U},
    {0x04220000U, 0x7aca4000U},
    {0x0426c5a0U, 0x7ac48000U},
    {0x0432283cU, 0x7ab7e800U},
    {0x04404898U, 0x7aaa6800U},
    {0x04409401U, 0x7aaa2800U},
    {0x04409811U, 0x7aaa2800U},
    {0x04415998U, 0x7aa97800U},
    {0x04440000U, 0x7aa73000U},
    {0x04620006U, 0x7a90f800U},
    {0x04802508U, 0x7a7fb800U},
    {0x04807512U, 0x7a7f2000U},
    {0x04819a16U, 0x7a7cd000U},
    {0x0484000aU, 0x7a783800U},
    {0x04a04243U, 0x7a4c7800U},
    {0x04a4cc05U, 0x7a46d800U},
    {0x05000008U, 0x79fff000U},
    {0x05020000U, 0x79fc0800U},
    {0x05108804U, 0x79e2b000U},
    {0x051a0808U, 0x79d4b800U},
    {0x053227d7U, 0x79b7f000U},
    {0x05841004U, 0x79782000U},
    {0x0584c89aU, 0x7976c000U},
    {0x05901a4aU, 0x79636000U},
    {0x06044102U, 0x78f7c000U},
    {0x06100040U, 0x78e38000U},
    {0x06110000U, 0x78e1f000U},
    {0x0615908cU, 0x78db1000U},
    {0x06495312U, 0x78a2c000U},
    {0x065147a2U, 0x789c9800U},
    {0x0658444aU, 0x78978800U},
    {0x065a7254U, 0x78960800U},
    {0x07120500U, 0x77e06800U},
    {0x08000000U, 0x76fff000U},
    {0x08000002U, 0x76fff000U},
    {0x0800000aU, 0x76fff000U},
    {0x08000040U, 0x76fff000U},
    {0x08000080U, 0x76fff000U},
    {0x08000200U, 0x76fff000U},
    {0x08000205U, 0x76fff000U},
    {0x08000440U, 0x76fff000U},
    {0x08000500U, 0x76fff000U},
    {0x08002011U, 0x76ffb800U},
    {0x08004010U, 0x76ff7800U},
    {0x08008000U, 0x76fef000U},
    {0x08008006U, 0x76fef000U},
    {0x08013004U, 0x76fda000U},
    {0x08018804U, 0x76fce800U},
    {0x08040000U, 0x76f83800U},
    {0x08050400U, 0x76f65800U},
    {0x08054000U, 0x76f5e000U},
    {0x08080020U, 0x76f0e000U},
    {0x08080040U, 0x76f0e000U},
    {0x080a0010U, 0x76ed6800U},
    {0x08200000U, 0x76ccc000U},
    {0x08200408U, 0x76ccc000U},
    {0x08308084U, 0x76b9a000U},
    {0x08448044U, 0x76a6c000U},
    {0x0856a545U, 0x7698a800U},
    {0x08800283U, 0x767ff000U},
    {0x08811000U, 0x767de000U},
    {0x08842080U, 0x76780000U},
    {0x0886000aU, 0x76748800U},
    {0x088c3400U, 0x7669b800U},
    {0x08a12708U, 0x764b6000U},
    {0x08a25142U, 0x7649e000U},
    {0x08b1aee8U, 0x76387000U},
    {0x08bc830cU, 0x762dd000U},
    {0x08c1a451U, 0x76293800U},
    {0x09000000U, 0x75fff000U},
    {0x09002080U, 0x75ffb800U},
    {0x093efc01U, 0x75ab9000U},
    {0x09800012U, 0x757ff000U},
    {0x0981e998U, 0x757c3800U},
    {0x098c102bU, 0x7569f000U},
    {0x09d010d1U, 0x751d7800U},
    {0x09d42020U, 0x751a7800U},
    {0x0a000441U, 0x74fff000U},
    {0x0a008395U, 0x74fef000U},
    {0x0a044000U, 0x74f7c000U},
    {0x0a219200U, 0x74cad000U},
    {0x0a826d00U, 0x747b4800U},
    {0x0a84e58aU, 0x74769800U},
    {0x0b10012bU, 0x73e38000U},
    {0x0c000000U, 0x72fff000U},
    {0x0c002006U, 0x72ffb800U},
    {0x0c020100U, 0x72fc0800U},
    {0x0c040200U, 0x72f83800U},
    {0x0c15a510U, 0x72db0000U},
    {0x0c32c2c3U, 0x72b75000U},
    {0x0c402120U, 0x72aa9000U},
    {0x0c420a90U, 0x72a8e000U},
    {0x0c81102cU, 0x727de000U},
    {0x0c8228deU, 0x727bc000U},
    {0x0c910022U, 0x7261f000U},
    {0x0c928c97U, 0x725f9800U},
    {0x0dab42c2U, 0x713f5800U},
    {0x10000000U, 0x6efff000U},
    {0x10000010U, 0x6efff000U},
    {0x10000080U, 0x6efff000U},
    {0x100001a0U, 0x6efff000U},
    {0x10000200U, 0x6efff000U},
    {0x10001040U, 0x6effd800U},
    {0x10002098U, 0x6effb800U},
    {0x10004000U, 0x6eff7800U},
    {0x10004440U, 0x6eff7800U},
    {0x10006000U, 0x6eff4000U},
    {0x10010810U, 0x6efde800U},
    {0x10010868U, 0x6efde800U},
    {0x10034122U, 0x6ef9a000U},
    {0x10040011U, 0x6ef83800U},
    {0x10041002U, 0x6ef82000U},
    {0x10042484U, 0x6ef80000U},
    {0x10048000U, 0x6ef74800U},
    {0x10060400U, 0x6ef48800U},
    {0x1007b000U, 0x6ef17800U},
    {0x10080000U, 0x6ef0e000U},
    {0x10149000U, 0x6edc8800U},
    {0x10205010U, 0x6ecc6000U},
    {0x10218c29U, 0x6ecad800U},
    {0x1021f390U, 0x6eca5800U},
    {0x10400000U, 0x6eaaa800U},
    {0x10404a90U, 0x6eaa6800U},
    {0x10408000U, 0x6eaa3800U},
    {0x10410185U, 0x6ea9c000U},
    {0x10411000U, 0x6ea9b000U},
    {0x10414123U, 0x6ea98800U},
    {0x10422000U, 0x6ea8d000U},
    {0x1045e330U, 0x6ea59800U},
    {0x10601209U, 0x6e923800U},
    {0x10601800U, 0x6e923000U},
    {0x10621000U, 0x6e90f000U},
    {0x10800000U, 0x6e7ff000U},
    {0x10a80000U, 0x6e430800U},
    {0x10a8050aU, 0x6e430800U},
    {0x10b01810U, 0x6e3a1000U},
    {0x10c02000U, 0x6e2a9000U},
    {0x11001000U, 0x6dffd800U},
    {0x11120004U, 0x6de06800U},
    {0x11221030U, 0x6dca3000U},
    {0x11408446U, 0x6daa3800U},
    {0x116283feU, 0x6d90a800U},
    {0x11802154U, 0x6d7fb800U},
    {0x11813104U, 0x6d7da000U},
    {0x1182a044U, 0x6d7ad800U},
    {0x11a414c2U, 0x6d47b800U},
    {0x1200a011U, 0x6cfeb800U},
    {0x1204a010U, 0x6cf71000U},
    {0x12204440U, 0x6ccc7800U},
    {0x12608000U, 0x6c91f000U},
    {0x12812020U, 0x6c7dc000U},
    {0x12828704U, 0x6c7b1000U},
    {0x12949040U, 0x6c5c8800U},
    {0x129e668dU, 0x6c4ee000U},
    {0x12c00002U, 0x6c2aa800U},
    {0x132023f3U, 0x6bcca000U},
    {0x13822821U, 0x6b7bc000U},
    {0x14001521U, 0x6affd800U},
    {0x14002010U, 0x6affb800U},
    {0x141c4320U, 0x6ad1b800U},
    {0x14208208U, 0x6acc2000U},
    {0x142365e6U, 0x6ac89000U},
    {0x142a2942U, 0x6ac09000U},
    {0x142a3004U, 0x6ac08800U},
    {0x142c80bcU, 0x6abdf800U},
    {0x14580004U, 0x6a97b000U},
    {0x14b7d812U, 0x6a323800U},
    {0x1506a03bU, 0x69f36800U},
    {0x15081402U, 0x69f0c800U},
    {0x15244158U, 0x69c78000U},
    {0x1591800fU, 0x69612800U},
    {0x15cd28c9U, 0x691fb800U},
    {0x15f1384cU, 0x6907d800U},
    {0x16137015U, 0x68de4000U},
    {0x161ca961U, 0x68d12800U},
    {0x16980374U, 0x68578800U},
    {0x18000000U, 0x66fff000U},
    {0x18000041U, 0x66fff000U},
    {0x18000090U, 0x66fff000U},
    {0x18100c25U, 0x66e37800U},
    {0x181a4242U, 0x66d47000U},
    {0x18352360U, 0x66b4e800U},
    {0x184d1a1aU, 0x669fc800U},
    {0x18826351U, 0x667b5800U},
    {0x18aa8484U, 0x66403000U},
    {0x19013800U, 0x65fd9000U},
    {0x19b06710U, 0x6539c800U},
    {0x1a000000U, 0x64fff000U},
    {0x1a0140d8U, 0x64fd8000U},
    {0x1b26b601U, 0x63c49000U},
    {0x1c054df5U, 0x62f5d000U},
    {0x1ce48240U, 0x620f6000U},
    {0x1e410030U, 0x60a9c000U},
    {0x1f82a95dU, 0x5f7ac800U},
    {0x20000000U, 0x5efff000U},
    {0x20000004U, 0x5efff000U},
    {0x20000008U, 0x5efff000U},
    {0x20000021U, 0x5efff000U},
    {0x20000040U, 0x5efff000U},
    {0x20000080U, 0x5efff000U},
    {0x20000100U, 0x5efff000U},
    {0x20000200U, 0x5efff000U},
    {0x20000400U, 0x5efff000U},
    {0x20000800U, 0x5effe000U},
    {0x20000822U, 0x5effe000U},
    {0x20000e80U, 0x5effe000U},
    {0x20001080U, 0x5effd800U},
    {0x20001100U, 0x5effd800U},
    {0x20004000U, 0x5eff7800U},
    {0x20004041U, 0x5eff7800U},
    {0x20004100U, 0x5eff7800U},
    {0x20006120U, 0x5eff4000U},
    {0x20008000U, 0x5efef000U},
    {0x200080a0U, 0x5efef000U},
    {0x20010000U, 0x5efdf800U},
    {0x20014080U, 0x5efd8000U},
    {0x20014421U, 0x5efd8000U},
    {0x20020006U, 0x5efc0800U},
    {0x20034400U, 0x5ef9a000U},
    {0x20040000U, 0x5ef83800U},
    {0x20080000U, 0x5ef0e000U},
    {0x20080054U, 0x5ef0e000U},
    {0x2008a048U, 0x5eefd000U},
    {0x20100000U, 0x5ee38000U},
    {0x20188340U, 0x5ed6d800U},
    {0x20200422U, 0x5eccc000U},
    {0x20208020U, 0x5ecc2000U},
    {0x20208990U, 0x5ecc1800U},
    {0x20210001U, 0x5ecb8000U},
    {0x20400000U, 0x5eaaa800U},
    {0x20400100U, 0x5eaaa800U},
    {0x20700032U, 0x5e888000U},
    {0x20800000U, 0x5e7ff000U},
    {0x20840000U, 0x5e783800U},
    {0x208420d0U, 0x5e780000U},
    {0x20854458U, 0x5e75e000U},
    {0x2087128aU, 0x5e72a000U},
    {0x20880210U, 0x5e70e000U},
    {0x20980002U, 0x5e578800U},
    {0x20a304e0U, 0x5e490000U},
    {0x210a2929U, 0x5ded2800U},
    {0x210a4014U, 0x5ded0000U},
    {0x212a0ee8U, 0x5dc0b800U},
    {0x21317041U, 0x5db8b000U},
    {0x214100c2U, 0x5da9c000U},
    {0x21424004U, 0x5da8b000U},
    {0x2148030eU, 0x5da3d000U},
    {0x21602101U, 0x5d923000U},
    {0x21719a84U, 0x5d87a000U},
    {0x21d2857eU, 0x5d1ba800U},
    {0x21e260c0U, 0x5d10c000U},
    {0x22018a88U, 0x5cfce800U},
    {0x22098001U, 0x5cee4800U},
    {0x22210806U, 0x5ccb7800U},
    {0x22244002U, 0x5cc78000U},
    {0x2240a100U, 0x5caa2000U},
    {0x22500480U, 0x5c9d8800U},
    {0x22540000U, 0x5c9a9000U},
    {0x22c28700U, 0x5c287800U},
    {0x23004900U, 0x5bff6800U},
    {0x23090200U, 0x5bef2000U},
    {0x23400006U, 0x5baaa800U},
    {0x23412054U, 0x5ba9a800U},
    {0x24000001U, 0x5afff000U},
    {0x24000840U, 0x5affe000U},
    {0x24002806U, 0x5affa800U},
    {0x24008000U, 0x5afef000U},
    {0x24218110U, 0x5acae000U},
    {0x2440d870U, 0x5aa9f000U},
    {0x24428008U, 0x5aa87800U},
    {0x24a140e6U, 0x5a4b3800U},
    {0x24b001e5U, 0x5a3a2800U},
    {0x24b0a266U, 0x5a398000U},
    {0x24cc1a90U, 0x5a209000U},
    {0x24f828b3U, 0x5a041000U},
    {0x25008014U, 0x59fef000U},
    {0x257b2604U, 0x59827800U},
    {0x25882124U, 0x5970b000U},
    {0x260531c8U, 0x58f60000U},
    {0x26452dc1U, 0x58a63000U},
    {0x26a02a52U, 0x584c9000U},
    {0x28000680U, 0x56fff000U},
    {0x28008000U, 0x56fef000U},
    {0x2815d068U, 0x56dab800U},
    {0x28216380U, 0x56cb1000U},
    {0x28424500U, 0x56a8b000U},
    {0x28444a55U, 0x56a6f000U},
    {0x28a42a40U, 0x56479800U},
    {0x2908d088U, 0x55ef8000U},
    {0x2913c20cU, 0x55ddc800U},
    {0x2924d839U, 0x55c6c800U},
    {0x299d5649U, 0x55504800U},
    {0x29c12482U, 0x5529a800U},
    {0x2a000400U, 0x54fff000U},
    {0x2a208b42U, 0x54cc1800U},
    {0x2add80c4U, 0x5413f000U},
    {0x30000300U, 0x4efff000U},
    {0x30034b80U, 0x4ef99000U},
    {0x30089cacU, 0x4eefd800U},
    {0x300c02e0U, 0x4eea0800U},
    {0x30322c13U, 0x4eb7e800U},
    {0x3098944fU, 0x4e56c800U},
    {0x30a1fd05U, 0x4e4a5000U},
    {0x31300010U, 0x4dba2800U},
    {0x3143fb88U, 0x4da73000U},
    {0x32176002U, 0x4cd87800U},
    {0x3240c018U, 0x4caa0000U},
    {0x328d04a0U, 0x4c686000U},
    {0x34404e04U, 0x4aaa6800U},
    {0x35149bd0U, 0x49dc8000U},
    {0x359478f3U, 0x495cb000U},
    {0x36825840U, 0x487b6800U},
    {0x37776a90U, 0x47847000U},
    {0x37840a50U, 0x47782800U},
    {0x381a0020U, 0x46d4c000U},
    {0x38950c18U, 0x465be000U},
    {0x3a59a5e1U, 0x44969000U},
    {0x3a92cb14U, 0x445f3800U},
    {0x3aa23e4aU, 0x444a0000U},
    {0x3b6c82a0U, 0x438a8800U},
    {0x3bbea670U, 0x432be000U},
    {0x3bfc6688U, 0x4301d800U},
    {0x3ce311a4U, 0x42105000U},
    {0x3d166d40U, 0x41d9d800U},
    {0x3f41277aU, 0x3fa9a800U},
    {0x40000000U, 0x3efff000U},
    {0x40000002U, 0x3efff000U},
    {0x40000040U, 0x3efff000U},
    {0x400000c1U, 0x3efff000U},
    {0x40000400U, 0x3efff000U},
    {0x40000408U, 0x3efff000U},
    {0x40000800U, 0x3effe000U},
    {0x40001001U, 0x3effd800U},
    {0x40001081U, 0x3effd800U},
    {0x40002010U, 0x3effb800U},
    {0x40002128U, 0x3effb800U},
    {0x40002400U, 0x3effb800U},
    {0x40004000U, 0x3eff7800U},
    {0x40010100U, 0x3efdf800U},
    {0x400112a0U, 0x3efde000U},
    {0x40020000U, 0x3efc0800U},
    {0x40020002U, 0x3efc0800U},
    {0x40020200U, 0x3efc0800U},
    {0x40023c00U, 0x3efba000U},
    {0x40040000U, 0x3ef83800U},
    {0x40090000U, 0x3eef2000U},
    {0x40098024U, 0x3eee4800U},
    {0x40100000U, 0x3ee38000U},
    {0x40100020U, 0x3ee38000U},
    {0x40104000U, 0x3ee32800U},
    {0x4012000bU, 0x3ee06800U},
    {0x4012a040U, 0x3edf7800U},
    {0x40201800U, 0x3ecca800U},
    {0x40220040U, 0x3eca4000U},
    {0x404000e1U, 0x3eaaa800U},
    {0x404020a1U, 0x3eaa9000U},
    {0x40404880U, 0x3eaa6800U},
    {0x40406020U, 0x3eaa5800U},
    {0x40440020U, 0x3ea73000U},
    {0x40458001U, 0x3ea5e800U},
    {0x40600492U, 0x3e924000U},
    {0x40800000U, 0x3e7ff000U},
    {0x40828105U, 0x3e7b1000U},
    {0x40840046U, 0x3e783800U},
    {0x4084a080U, 0x3e771000U},
    {0x40a00000U, 0x3e4cc000U},
    {0x40d07002U, 0x3e1d3800U},
    {0x40e11022U, 0x3e119800U},
    {0x4110d080U, 0x3de24800U},
    {0x41300052U, 0x3dba2800U},
    {0x414089acU, 0x3daa3000U},
    {0x41601840U, 0x3d923000U},
    {0x41808000U, 0x3d7ef000U},
    {0x41ae21eeU, 0x3d3c2800U},
    {0x42000000U, 0x3cfff000U},
    {0x42000004U, 0x3cfff000U},
    {0x4202cc4aU, 0x3cfa8800U},
    {0x42140000U, 0x3cdd6000U},
    {0x4220080aU, 0x3cccb800U},
    {0x422ea802U, 0x3cbb9800U},
    {0x42479208U, 0x3ca43000U},
    {0x42810402U, 0x3c7df800U},
    {0x43119905U, 0x3be10800U},
    {0x4331a1c2U, 0x3bb87800U},
    {0x43e0c084U, 0x3b11c800U},
    {0x44000080U, 0x3afff000U},
    {0x44010009U, 0x3afdf800U},
    {0x4401e084U, 0x3afc4800U},
    {0x44020050U, 0x3afc0800U},
    {0x44022054U, 0x3afbd000U},
    {0x44200000U, 0x3accc000U},
    {0x44602400U, 0x3a923000U},
    {0x44802002U, 0x3a7fb800U},
    {0x44829820U, 0x3a7ae800U},
    {0x44840100U, 0x3a783800U},
    {0x44a48b80U, 0x3a472800U},
    {0x44d000a0U, 0x3a1d8800U},
    {0x4500513bU, 0x39ff6000U},
    {0x45140c05U, 0x39dd5800U},
    {0x45148101U, 0x39dca000U},
    {0x45844200U, 0x3977c000U},
    {0x45b11402U, 0x39391000U},
    {0x45c185aaU, 0x39295000U},
    {0x46105600U, 0x38e31000U},
    {0x4620995dU, 0x38cc0800U},
    {0x468e1f00U, 0x38669800U},
    {0x46cbaaf4U, 0x3820e000U},
    {0x4717d544U, 0x37d7d800U},
    {0x4742b154U, 0x37a85000U},
    {0x474de6c8U, 0x379f2800U},
    {0x474ef708U, 0x379e5800U},
    {0x47676640U, 0x378da000U},
    {0x47805052U, 0x377f6000U},
    {0x47be311aU, 0x372c5000U},
    {0x48000080U, 0x36fff000U},
    {0x480a2812U, 0x36ed2800U},
    {0x49002018U, 0x35ffb800U},
    {0x49148320U, 0x35dca000U},
    {0x49900122U, 0x35638000U},
    {0x4a07587eU, 0x34f21800U},
    {0x4a30ad46U, 0x34b97800U},
    {0x4a610140U, 0x3491a000U},
    {0x4a8057c9U, 0x347f6000U},
    {0x4c000004U, 0x32fff000U},
    {0x4c00f18aU, 0x32fe2000U},
    {0x4c86c280U, 0x32732800U},
    {0x4d82ec1eU, 0x317a5000U},
    {0x4e880202U, 0x3070e000U},
    {0x4ee1a651U, 0x30113800U},
    {0x4f432104U, 0x2fa7f000U},
    {0x4f4e03a1U, 0x2f9f1000U},
    {0x50000200U, 0x2efff000U},
    {0x50000c84U, 0x2effe000U},
    {0x50118842U, 0x2ee12000U},
    {0x50400411U, 0x2eaaa800U},
    {0x504306d0U, 0x2ea80800U},
    {0x50844040U, 0x2e77c000U},
    {0x50b43946U, 0x2e35d000U},
    {0x50e82200U, 0x2e0d2800U},
    {0x510b0262U, 0x2debb800U},
    {0x51240001U, 0x2dc7c800U},
    {0x512f2013U, 0x2dbb1800U},
    {0x515e0088U, 0x2d939800U},
    {0x51843225U, 0x2d77e000U},
    {0x521355a1U, 0x2cde7000U},
    {0x52326270U, 0x2cb7b000U},
    {0x52d12262U, 0x2c1cb000U},
    {0x5301dac0U, 0x2bfc5800U},
    {0x54000000U, 0x2afff000U},
    {0x54206310U, 0x2acc5000U},
    {0x54c04c48U, 0x2a2a6800U},
    {0x55314cb3U, 0x29b8d800U},
    {0x55555555U, 0x2999a000U},
    {0x5773839bU, 0x27869000U},
    {0x57d30942U, 0x271b4000U},
    {0x5801d009U, 0x26fc6800U},
    {0x585c0a80U, 0x2694e800U},
    {0x58d00880U, 0x261d8000U},
    {0x58eda011U, 0x2609e800U},
    {0x59438c95U, 0x25a79000U},
    {0x595cee3dU, 0x25945000U},
    {0x596e6a60U, 0x25897000U},
    {0x5c6336d8U, 0x22904000U},
    {0x60000100U, 0x1efff000U},
    {0x60000548U, 0x1efff000U},
    {0x60002dffU, 0x1effa800U},
    {0x60208919U, 0x1ecc1800U},
    {0x6030b48aU, 0x1eb97000U},
    {0x60500108U, 0x1e9d8800U},
    {0x60940048U, 0x1e5d6000U},
    {0x60c600a4U, 0x1e258000U},
    {0x60d14626U, 0x1e1c9800U},
    {0x61083821U, 0x1df08800U},
    {0x61200001U, 0x1dccc000U},
    {0x6182e42aU, 0x1d7a6000U},
    {0x61c09343U, 0x1d2a2800U},
    {0x61de5fa1U, 0x1d136000U},
    {0x62008b11U, 0x1cfee000U},
    {0x62204c2aU, 0x1ccc6800U},
    {0x639326d0U, 0x1b5eb800U},
    {0x64065304U, 0x1af3f800U},
    {0x64a04106U, 0x1a4c7800U},
    {0x64a30127U, 0x1a490000U},
    {0x652d0989U, 0x19bd6000U},
    {0x6531124fU, 0x19b91000U},
    {0x6702a07fU, 0x17fad800U},
    {0x6803410cU, 0x16f9a000U},
    {0x6a0f00c8U, 0x14e52000U},
    {0x6c1c9022U, 0x12d14800U},
    {0x6c809ee0U, 0x127ec800U},
    {0x6e094188U, 0x10eeb800U},
    {0x70200104U, 0x0eccc000U},
    {0x70ca818cU, 0x0e21d000U},
    {0x71d04100U, 0x0d1d5800U},
    {0x7298ae28U, 0x0c56a800U},
    {0x72ada40aU, 0x0c3cb800U},
    {0x7349957fU, 0x0ba29000U},
    {0x74a80d01U, 0x0a430000U},
    {0x761807c1U, 0x08d78800U},
    {0x77e31951U, 0x07104800U},
    {0x7ad94e40U, 0x0416d000U},
    {0x7b771502U, 0x0384a000U},
    {0x7ffffffdU, 0x7ffffffdU},
    {0x80000000U, 0xff800000U},
    {0x80000002U, 0xff800000U},
    {0x80000005U, 0xff800000U},
    {0x80000008U, 0xff800000U},
    {0x80000020U, 0xff800000U},
    {0x8000004cU, 0xff800000U},
    {0x80000080U, 0xff800000U},
    {0x80000101U, 0xff800000U},
    {0x80000400U, 0xff800000U},
    {0x80001000U, 0xff800000U},
    {0x80002000U, 0xff800000U},
    {0x80004000U, 0xff800000U},
    {0x80004044U, 0xff800000U},
    {0x80006001U, 0xff800000U},
    {0x80010000U, 0xff800000U},
    {0x80012048U, 0xff800000U},
    {0x80014100U, 0xff800000U},
    {0x80042e18U, 0xff800000U},
    {0x8005542cU, 0xff800000U},
    {0x80110e28U, 0xff800000U},
    {0x80120800U, 0xff800000U},
    {0x80204028U, 0xff800000U},
    {0x80213010U, 0xff800000U},
    {0x80400000U, 0xff800000U},
    {0x80446802U, 0xff800000U},
    {0x80800000U, 0xfe7ff000U},
    {0x80800800U, 0xfe7fe000U},
    {0x80808004U, 0xfe7ef000U},
    {0x80825002U, 0xfe7b7800U},
    {0x808faa58U, 0xfe641800U},
    {0x80903519U, 0xfe634000U},
    {0x80aa21e1U, 0xfe409800U},
    {0x80c00218U, 0xfe2aa800U},
    {0x80e80009U, 0xfe0d3800U},
    {0x8106005aU, 0xfdf48800U},
    {0x81130800U, 0xfdded800U},
    {0x81200002U, 0xfdccc000U},
    {0x812956e2U, 0xfdc18800U},
    {0x81422003U, 0xfda8d000U},
    {0x8164076eU, 0xfd8fb000U},
    {0x81820080U, 0xfd7c0800U},
    {0x818b538aU, 0xfd6b3800U},
    {0x81ae1458U, 0xfd3c4000U},
    {0x82000000U, 0xfcfff000U},
    {0x82040000U, 0xfcf83800U},
    {0x820f1043U, 0xfce50800U},
    {0x8236a071U, 0xfcb37000U},
    {0x82508800U, 0xfc9d2000U},
    {0x83000100U, 0xfbfff000U},
    {0x830a0084U, 0xfbed6800U},
    {0x83642011U, 0xfb8fa000U},
    {0x83a6ba88U, 0xfb448800U},
    {0x84000000U, 0xfafff000U},
    {0x84000001U, 0xfafff000U},
    {0x84005c48U, 0xfaff5000U},
    {0x84010520U, 0xfafdf800U},
    {0x84019c01U, 0xfafcd000U},
    {0x84021000U, 0xfafbf000U},
    {0x8408d0c5U, 0xfaef8000U},
    {0x841acc9aU, 0xfad3b000U},
    {0x84200100U, 0xfaccc000U},
    {0x84221423U, 0xfaca3000U},
    {0x84402010U, 0xfaaa9000U},
    {0x84421000U, 0xfaa8d800U},
    {0x844450a0U, 0xfaa6f000U},
    {0x84785280U, 0xfa83f800U},
    {0x84810281U, 0xfa7df800U},
    {0x8502091aU, 0xf9fbf800U},
    {0x8502c61bU, 0xf9fa9800U},
    {0x85da0015U, 0xf9165000U},
    {0x86a05700U, 0xf84c6000U},
    {0x86a70533U, 0xf8443000U},
    {0x86aebdf2U, 0xf83b8800U},
    {0x870106dfU, 0xf7fdf800U},
    {0x88000003U, 0xf6fff000U},
    {0x8800c604U, 0xf6fe7800U},
    {0x8800e000U, 0xf6fe4000U},
    {0x88016000U, 0xf6fd4800U},
    {0x88029222U, 0xf6faf800U},
    {0x886048bbU, 0xf6921800U},
    {0x88820305U, 0xf67c0800U},
    {0x89001404U, 0xf5ffd800U},
    {0x89c20086U, 0xf528e800U},
    {0x8a001280U, 0xf4ffd800U},
    {0x8a100420U, 0xf4e38000U},
    {0x8a5dc05dU, 0xf493c800U},
    {0x8b0460aaU, 0xf3f78800U},
    {0x8d002006U, 0xf1ffb800U},
    {0x8e4406c5U, 0xf0a73000U},
    {0x90000022U, 0xeefff000U},
    {0x90000200U, 0xeefff000U},
    {0x9000020eU, 0xeefff000U},
    {0x90001006U, 0xeeffd800U},
    {0x90003d51U, 0xeeff8800U},
    {0x90011100U, 0xeefde000U},
    {0x900129b1U, 0xeefdb000U},
    {0x90400008U, 0xeeaaa800U},
    {0x90800002U, 0xee7ff000U},
    {0x90a08083U, 0xee4c2000U},
    {0x91220628U, 0xedca4000U},
    {0x918e9741U, 0xed65d800U},
    {0x91a13a8cU, 0xed4b4000U},
    {0x922715f9U, 0xecc42000U},
    {0x92380025U, 0xecb21000U},
    {0x92b20862U, 0xec380800U},
    {0x93884522U, 0xeb707800U},
    {0x94112d89U, 0xeae1b800U},
    {0x948206caU, 0xea7c0800U},
    {0x9540a980U, 0xe9aa1800U},
    {0x96320038U, 0xe8b81000U},
    {0x98020a05U, 0xe6fbf800U},
    {0x984a8e41U, 0xe6a1c800U},
    {0x98500255U, 0xe69d8800U},
    {0x99008200U, 0xe5fef000U},
    {0x9a443040U, 0xe4a70800U},
    {0x9bd00f58U, 0xe31d8000U},
    {0x9c088245U, 0xe2f00000U},
    {0x9d926420U, 0xe15fe000U},
    {0xa000c000U, 0xdefe7800U},
    {0xa0280055U, 0xdec30800U},
    {0xa03c6f03U, 0xdeade800U},
    {0xa04012a0U, 0xdeaa9800U},
    {0xa08a7d0aU, 0xde6ca000U},
    {0xa08fb588U, 0xde640800U},
    {0xa0902105U, 0xde635800U},
    {0xa0a10405U, 0xde4b8000U},
    {0xa0c99c80U, 0xde228800U},
    {0xa1a0c864U, 0xdd4bc800U},
    {0xa2092f0dU, 0xdceee000U},
    {0xa2407080U, 0xdcaa4800U},
    {0xa40c2148U, 0xdae9d800U},
    {0xa4126b06U, 0xdadfd000U},
    {0xa4841284U, 0xda782000U},
    {0xa4880400U, 0xda70e000U},
    {0xa78170e1U, 0xd77d2800U},
    {0xa8001084U, 0xd6ffd800U},
    {0xa8020100U, 0xd6fc0800U},
    {0xa8220524U, 0xd6ca4000U},
    {0xab88010dU, 0xd370e000U},
    {0xac908080U, 0xd262b800U},
    {0xb0029808U, 0xcefae800U},
    {0xb0112147U, 0xcee1c800U},
    {0xb0ce00c1U, 0xce1f1000U},
    {0xb1432118U, 0xcda7f000U},
    {0xb1804a58U, 0xcd7f6800U},
    {0xb2010040U, 0xccfdf800U},
    {0xb22900a5U, 0xccc1e000U},
    {0xb2c908f1U, 0xcc22f800U},
    {0xb67293a6U, 0xc8871000U},
    {0xb82d1f45U, 0xc6bd4800U},
    {0xbb47116aU, 0xc3a49800U},
    {0xbb80c041U, 0xc37e7800U},
    {0xbdab4207U, 0xc13f5800U},
    {0xc0000000U, 0xbefff000U},
    {0xc0000004U, 0xbefff000U},
    {0xc006c820U, 0xbef31800U},
    {0xc00fad4aU, 0xbee41800U},
    {0xc01a0094U, 0xbed4c000U},
    {0xc020410eU, 0xbecc7800U},
    {0xc0285342U, 0xbec2b000U},
    {0xc0410004U, 0xbea9c000U},
    {0xc04218a6U, 0xbea8d800U},
    {0xc0541208U, 0xbe9a8000U},
    {0xc077044aU, 0xbe84a800U},
    {0xc089a23fU, 0xbe6e1800U},
    {0xc0904002U, 0xbe632800U},
    {0xc0b30544U, 0xbe371000U},
    {0xc1048092U, 0xbdf74800U},
    {0xc2ca9064U, 0xbc21c800U},
    {0xc4846824U, 0xba777800U},
    {0xc486c1caU, 0xba732800U},
    {0xc49c0d18U, 0xba520000U},
    {0xc4f8c2d3U, 0xba03b800U},
    {0xc583a140U, 0xb978f000U},
    {0xc5dc34c0U, 0xb914d000U},
    {0xc5e08000U, 0xb911f000U},
    {0xc62d008aU, 0xb8bd6800U},
    {0xc6a47e00U, 0xb8473800U},
    {0xc6b91f84U, 0xb8310000U},
    {0xc6bc2710U, 0xb82e2800U},
    {0xc7513b8cU, 0xb79ca000U},
    {0xc77a42dbU, 0xb782f000U},
    {0xc79bd335U, 0xb7524800U},
    {0xc79e7eb4U, 0xb74ec000U},
    {0xc841a900U, 0xb6a93000U},
    {0xc8a0b540U, 0xb64be800U},
    {0xc8a60000U, 0xb6456000U},
    {0xc8c2d024U, 0xb6283800U},
    {0xc9009000U, 0xb5fed800U},
    {0xc942b0a3U, 0xb5a85000U},
    {0xc9d79340U, 0xb5180000U},
    {0xca28d085U, 0xb4c22000U},
    {0xcc008000U, 0xb2fef000U},
    {0xce0521c1U, 0xb0f62000U},
    {0xd00a1783U, 0xaeed5000U},
    {0xd00f10c6U, 0xaee50800U},
    {0xd04595aaU, 0xaea5d800U},
    {0xd080325cU, 0xae7f9800U},
    {0xd0a4d40aU, 0xae46d000U},
    {0xd1ce803eU, 0xad1eb000U},
    {0xd2d916eeU, 0xac16f800U},
    {0xd33d6028U, 0xabad0800U},
    {0xd63cc600U, 0xa8ad9800U},
    {0xdcc0cf29U, 0xa229f800U},
    {0xde2e8cc3U, 0xa0bbc000U},
    {0xe0100100U, 0x9ee38000U},
    {0xe0681154U, 0x9e8d3000U},
    {0xe0c47080U, 0x9e26d000U},
    {0xe1074342U, 0x9df24000U},
    {0xe1f94214U, 0x9d037800U},
    {0xe3bb79abU, 0x9b2ec800U},
    {0xe4144040U, 0x9add0800U},
    {0xe454a298U, 0x9a9a1800U},
    {0xe502c646U, 0x99fa9800U},
    {0xe6bc0385U, 0x982e4800U},
    {0xe8011680U, 0x96fde000U},
    {0xe8254c15U, 0x96c63800U},
    {0xe988a405U, 0x956fd000U},
    {0xec4d0a5cU, 0x929fd000U},
    {0xec8fc01aU, 0x9263f000U},
    {0xf343a4e2U, 0x8ba78000U},
    {0xf3ba491fU, 0x8b2fe800U},
    {0xf540060bU, 0x89aaa800U},
    {0xf628a819U, 0x88c24800U},
    {0xff513f9dU, 0x80000000U},
    {0xff8000ffU, 0xffc000ffU},
    {0xfffffffeU, 0xfffffffeU},
    {0xffffffffU, 0xffffffffU},
};

static constexpr ApproxFpPair kApproxRsqrt32Table[] = {
    {0x00000000U, 0x7f800000U},
    {0x00000001U, 0x7f800000U},
    {0x00000002U, 0x7f800000U},
    {0x00000004U, 0x7f800000U},
    {0x00000006U, 0x7f800000U},
    {0x00000008U, 0x7f800000U},
    {0x00000009U, 0x7f800000U},
    {0x0000000aU, 0x7f800000U},
    {0x00000010U, 0x7f800000U},
    {0x00000020U, 0x7f800000U},
    {0x00000030U, 0x7f800000U},
    {0x00000040U, 0x7f800000U},
    {0x00000060U, 0x7f800000U},
    {0x00000080U, 0x7f800000U},
    {0x00000100U, 0x7f800000U},
    {0x00000108U, 0x7f800000U},
    {0x00000200U, 0x7f800000U},
    {0x00000400U, 0x7f800000U},
    {0x00000401U, 0x7f800000U},
    {0x00000420U, 0x7f800000U},
    {0x00000800U, 0x7f800000U},
    {0x00000802U, 0x7f800000U},
    {0x00000808U, 0x7f800000U},
    {0x0000080aU, 0x7f800000U},
    {0x00000869U, 0x7f800000U},
    {0x00001000U, 0x7f800000U},
    {0x00001044U, 0x7f800000U},
    {0x00001300U, 0x7f800000U},
    {0x00001400U, 0x7f800000U},
    {0x00002000U, 0x7f800000U},
    {0x00002080U, 0x7f800000U},
    {0x00002082U, 0x7f800000U},
    {0x00002803U, 0x7f800000U},
    {0x00002860U, 0x7f800000U},
    {0x00003200U, 0x7f800000U},
    {0x00003580U, 0x7f800000U},
    {0x00004000U, 0x7f800000U},
    {0x0000418dU, 0x7f800000U},
    {0x00004800U, 0x7f800000U},
    {0x00008000U, 0x7f800000U},
    {0x0000800cU, 0x7f800000U},
    {0x0000ab04U, 0x7f800000U},
    {0x0000c000U, 0x7f800000U},
    {0x00010000U, 0x7f800000U},
    {0x00010140U, 0x7f800000U},
    {0x00010d4aU, 0x7f800000U},
    {0x00011000U, 0x7f800000U},
    {0x00012000U, 0x7f800000U},
    {0x00020000U, 0x7f800000U},
    {0x00020100U, 0x7f800000U},
    {0x0002100aU, 0x7f800000U},
    {0x00021100U, 0x7f800000U},
    {0x00030463U, 0x7f800000U},
    {0x0003a290U, 0x7f800000U},
    {0x00040000U, 0x7f800000U},
    {0x00042042U, 0x7f800000U},
    {0x0004400cU, 0x7f800000U},
    {0x00044040U, 0x7f800000U},
    {0x00048200U, 0x7f800000U},
    {0x00078284U, 0x7f800000U},
    {0x00080000U, 0x7f800000U},
    {0x00080410U, 0x7f800000U},
    {0x00082000U, 0x7f800000U},
    {0x0008a020U, 0x7f800000U},
    {0x0008ba14U, 0x7f800000U},
    {0x000a1c09U, 0x7f800000U},
    {0x000c0000U, 0x7f800000U},
    {0x00100000U, 0x7f800000U},
    {0x0010000eU, 0x7f800000U},
    {0x00100024U, 0x7f800000U},
    {0x00100100U, 0x7f800000U},
    {0x00102000U, 0x7f800000U},
    {0x00102400U, 0x7f800000U},
    {0x00104040U, 0x7f800000U},
    {0x00110000U, 0x7f800000U},
    {0x00112048U, 0x7f800000U},
    {0x00120000U, 0x7f800000U},
    {0x00142200U, 0x7f800000U},
    {0x00158210U, 0x7f800000U},
    {0x00188210U, 0x7f800000U},
    {0x00200000U, 0x7f800000U},
    {0x00200083U, 0x7f800000U},
    {0x00200801U, 0x7f800000U},
    {0x00204c10U, 0x7f800000U},
    {0x00205080U, 0x7f800000U},
    {0x00208020U, 0x7f800000U},
    {0x00210244U, 0x7f800000U},
    {0x00212000U, 0x7f800000U},
    {0x0021a288U, 0x7f800000U},
    {0x00220a92U, 0x7f800000U},
    {0x00248000U, 0x7f800000U},
    {0x00248020U, 0x7f800000U},
    {0x00282061U, 0x7f800000U},
    {0x002a0880U, 0x7f800000U},
    {0x00351470U, 0x7f800000U},
    {0x00400000U, 0x7f800000U},
    {0x00400002U, 0x7f800000U},
    {0x00400100U, 0x7f800000U},
    {0x00401000U, 0x7f800000U},
    {0x00404004U, 0x7f800000U},
    {0x00404200U, 0x7f800000U},
    {0x00404280U, 0x7f800000U},
    {0x00408204U, 0x7f800000U},
    {0x00409001U, 0x7f800000U},
    {0x00410011U, 0x7f800000U},
    {0x00420008U, 0x7f800000U},
    {0x00422000U, 0x7f800000U},
    {0x00428403U, 0x7f800000U},
    {0x00440000U, 0x7f800000U},
    {0x0048800eU, 0x7f800000U},
    {0x004b5380U, 0x7f800000U},
    {0x00508888U, 0x7f800000U},
    {0x00542300U, 0x7f800000U},
    {0x00600050U, 0x7f800000U},
    {0x00600200U, 0x7f800000U},
    {0x00800000U, 0x5efff800U},
    {0x00800002U, 0x5efff800U},
    {0x00800008U, 0x5efff800U},
    {0x00800020U, 0x5efff800U},
    {0x00800080U, 0x5efff800U},
    {0x00800100U, 0x5efff800U},
    {0x00800200U, 0x5efff800U},
    {0x00800620U, 0x5efff800U},
    {0x00802000U, 0x5effd800U},
    {0x00802048U, 0x5effd800U},
    {0x00802100U, 0x5effd800U},
    {0x00802a40U, 0x5effd000U},
    {0x00804211U, 0x5effc000U},
    {0x00804433U, 0x5effc000U},
    {0x00808008U, 0x5eff7800U},
    {0x0080820cU, 0x5eff7800U},
    {0x0080e015U, 0x5eff2000U},
    {0x00810000U, 0x5efef800U},
    {0x00810200U, 0x5efef800U},
    {0x00822000U, 0x5efde000U},
    {0x00829811U, 0x5efd6800U},
    {0x00834004U, 0x5efcd000U},
    {0x00840482U, 0x5efc1000U},
    {0x00844801U, 0x5efbd000U},
    {0x00880000U, 0x5ef85800U},
    {0x00880004U, 0x5ef85800U},
    {0x008c0000U, 0x5ef4c800U},
    {0x009080f8U, 0x5ef0f000U},
    {0x0090a154U, 0x5ef0d800U},
    {0x009213a5U, 0x5eefa000U},
    {0x00a00040U, 0x5ee4f000U},
    {0x00a01c05U, 0x5ee4e000U},
    {0x00a20901U, 0x5ee38800U},
    {0x00a40000U, 0x5ee22800U},
    {0x00b00900U, 0x5eda5000U},
    {0x00c00d20U, 0x5ed10000U},
    {0x00c100c2U, 0x5ed07800U},
    {0x01000000U, 0x5eb50000U},
    {0x01000004U, 0x5eb50000U},
    {0x0100000dU, 0x5eb50000U},
    {0x01000051U, 0x5eb50000U},
    {0x01000080U, 0x5eb50000U},
    {0x01000181U, 0x5eb50000U},
    {0x01000404U, 0x5eb50000U},
    {0x01000800U, 0x5eb4f800U},
    {0x01002000U, 0x5eb4e800U},
    {0x01004420U, 0x5eb4d800U},
    {0x01008000U, 0x5eb4a800U},
    {0x010080c0U, 0x5eb4a800U},
    {0x01018140U, 0x5eb3f000U},
    {0x01020008U, 0x5eb39800U},
    {0x01040004U, 0x5eb24000U},
    {0x01051080U, 0x5eb19000U},
    {0x01080010U, 0x5eaf9800U},
    {0x01080100U, 0x5eaf9800U},
    {0x01082092U, 0x5eaf8800U},
    {0x010a14d8U, 0x5eae4800U},
    {0x01100000U, 0x5eaaa800U},
    {0x01104008U, 0x5eaa8800U},
    {0x011044a4U, 0x5eaa8800U},
    {0x01180120U, 0x5ea61800U},
    {0x01202009U, 0x5ea1d800U},
    {0x01208000U, 0x5ea1a800U},
    {0x01310011U, 0x5e99f000U},
    {0x01400000U, 0x5e93c800U},
    {0x01440003U, 0x5e924800U},
    {0x0144c809U, 0x5e920000U},
    {0x01550400U, 0x5e8c5000U},
    {0x0160358cU, 0x5e88c000U},
    {0x01800000U, 0x5e7ff800U},
    {0x01800012U, 0x5e7ff800U},
    {0x0180a104U, 0x5e7f5800U},
    {0x01848577U, 0x5e7b9800U},
    {0x0187c048U, 0x5e789800U},
    {0x018c0012U, 0x5e74c800U},
    {0x019a8001U, 0x5e690000U},
    {0x02000000U, 0x5e350000U},
    {0x02000001U, 0x5e350000U},
    {0x02000002U, 0x5e350000U},
    {0x02000008U, 0x5e350000U},
    {0x02000068U, 0x5e350000U},
    {0x02000088U, 0x5e350000U},
    {0x02000200U, 0x5e350000U},
    {0x02000800U, 0x5e34f800U},
    {0x02001004U, 0x5e34f800U},
    {0x02002e41U, 0x5e34e800U},
    {0x02004000U, 0x5e34d800U},
    {0x02004220U, 0x5e34d800U},
    {0x02004800U, 0x5e34d000U},
    {0x02009000U, 0x5e34a000U},
    {0x02010000U, 0x5e345000U},
    {0x020163fdU, 0x5e341000U},
    {0x02020880U, 0x5e339000U},
    {0x02022008U, 0x5e338000U},
    {0x02024200U, 0x5e337000U},
    {0x02040000U, 0x5e324000U},
    {0x02040800U, 0x5e323800U},
    {0x02083170U, 0x5e2f8000U},
    {0x02084108U, 0x5e2f7000U},
    {0x020c0490U, 0x5e2d1000U},
    {0x02100146U, 0x5e2aa800U},
    {0x02108000U, 0x5e2a5800U},
    {0x02200000U, 0x5e21e800U},
    {0x02216002U, 0x5e213800U},
    {0x02242900U, 0x5e1fd800U},
    {0x02250008U, 0x5e1f7000U},
    {0x02300142U, 0x5e1a6000U},
    {0x0230b004U, 0x5e1a1800U},
    {0x02400000U, 0x5e13c800U},
    {0x02400842U, 0x5e13c800U},
    {0x02409882U, 0x5e139000U},
    {0x0243d842U, 0x5e125800U},
    {0x02800408U, 0x5dfff800U},
    {0x02808800U, 0x5dff7000U},
    {0x02820500U, 0x5dfe0000U},
    {0x02a11b63U, 0x5de43000U},
    {0x02d384e7U, 0x5dc72800U},
    {0x02ddc891U, 0x5dc28000U},
    {0x030141a0U, 0x5db42800U},
    {0x03036e20U, 0x5db2a800U},
    {0x034441a1U, 0x5d923000U},
    {0x036179a0U, 0x5d886800U},
    {0x03800002U, 0x5d7ff800U},
    {0x03b03024U, 0x5d5a3800U},
    {0x04000000U, 0x5d350000U},
    {0x04000040U, 0x5d350000U},
    {0x04000401U, 0x5d350000U},
    {0x040004a0U, 0x5d350000U},
    {0x04000906U, 0x5d34f800U},
    {0x04005606U, 0x5d34c800U},
    {0x04008000U, 0x5d34a800U},
    {0x04020000U, 0x5d339800U},
    {0x04020a30U, 0x5d339000U},
    {0x04022002U, 0x5d338000U},
    {0x04024800U, 0x5d336800U},
    {0x04030180U, 0x5d32f000U},
    {0x04040000U, 0x5d324000U},
    {0x04040008U, 0x5d324000U},
    {0x04040200U, 0x5d324000U},
    {0x0404c3c8U, 0x5d31c000U},
    {0x04071004U, 0x5d303800U},
    {0x040800aaU, 0x5d2f9800U},
    {0x040a2882U, 0x5d2e3800U},
    {0x040d4942U, 0x5d2c5000U},
    {0x04100000U, 0x5d2aa800U},
    {0x04100020U, 0x5d2aa800U},
    {0x04100021U, 0x5d2aa800U},
    {0x04104001U, 0x5d2a8800U},
    {0x0410e000U, 0x5d2a2000U},
    {0x04150010U, 0x5d27c800U},
    {0x0419390aU, 0x5d257000U},
    {0x04200034U, 0x5d21e800U},
    {0x04210020U, 0x5d216800U},
    {0x04254252U, 0x5d1f5000U},
    {0x04286240U, 0x5d1dd000U},
    {0x042c0008U, 0x5d1c2800U},
    {0x043ca0e4U, 0x5d151800U},
    {0x044060c2U, 0x5d13a800U},
    {0x04408003U, 0x5d139800U},
    {0x04432474U, 0x5d12a000U},
    {0x04500000U, 0x5d0e0000U},
    {0x046203a1U, 0x5d083800U},
    {0x04801500U, 0x5cffe800U},
    {0x04840406U, 0x5cfc1000U},
    {0x0487191eU, 0x5cf92800U},
    {0x04f402bcU, 0x5cb96800U},
    {0x05000400U, 0x5cb50000U},
    {0x05004100U, 0x5cb4d800U},
    {0x05020010U, 0x5cb39800U},
    {0x050280a0U, 0x5cb34800U},
    {0x050c1831U, 0x5cad0000U},
    {0x050d36cdU, 0x5cac6000U},
    {0x05100194U, 0x5caaa800U},
    {0x052d64e4U, 0x5c9b8800U},
    {0x05880210U, 0x5c785800U},
    {0x059b0874U, 0x5c689800U},
    {0x05e01080U, 0x5c417800U},
    {0x05e400acU, 0x5c3fd000U},
    {0x06000010U, 0x5c350000U},
    {0x06001010U, 0x5c34f800U},
    {0x06004012U, 0x5c34d800U},
    {0x06008208U, 0x5c34a800U},
    {0x06400381U, 0x5c13c800U},
    {0x06604040U, 0x5c08c000U},
    {0x07184b21U, 0x5ba5f000U},
    {0x07900218U, 0x5b715800U},
    {0x07900a12U, 0x5b715000U},
    {0x0793538eU, 0x5b6ea000U},
    {0x08000000U, 0x5b350000U},
    {0x08000001U, 0x5b350000U},
    {0x08000008U, 0x5b350000U},
    {0x08000020U, 0x5b350000U},
    {0x08000100U, 0x5b350000U},
    {0x08000400U, 0x5b350000U},
    {0x080010d9U, 0x5b34f800U},
    {0x08002000U, 0x5b34e800U},
    {0x08004808U, 0x5b34d000U},
    {0x0800d000U, 0x5b347000U},
    {0x08010004U, 0x5b345000U},
    {0x08010021U, 0x5b345000U},
    {0x08020482U, 0x5b339800U},
    {0x08048158U, 0x5b31e800U},
    {0x0808080aU, 0x5b2f9800U},
    {0x08082502U, 0x5b2f8800U},
    {0x080c0000U, 0x5b2d1000U},
    {0x08100010U, 0x5b2aa800U},
    {0x08102004U, 0x5b2a9800U},
    {0x08120440U, 0x5b297800U},
    {0x0812230eU, 0x5b296800U},
    {0x08204068U, 0x5b21c800U},
    {0x08210028U, 0x5b216800U},
    {0x08240020U, 0x5b1fe800U},
    {0x08400300U, 0x5b13c800U},
    {0x084080c2U, 0x5b139800U},
    {0x084222b8U, 0x5b130000U},
    {0x08440481U, 0x5b124800U},
    {0x08488002U, 0x5b10a000U},
    {0x08800000U, 0x5afff800U},
    {0x08800080U, 0x5afff800U},
    {0x08801000U, 0x5affe800U},
    {0x08804601U, 0x5affc000U},
    {0x08804800U, 0x5affb800U},
    {0x089c424fU, 0x5ae7b000U},
    {0x08d63a7bU, 0x5ac5e000U},
    {0x09000000U, 0x5ab50000U},
    {0x09080141U, 0x5aaf9800U},
    {0x09201d01U, 0x5aa1e000U},
    {0x09512534U, 0x5a8da000U},
    {0x09838200U, 0x5a7c9000U},
    {0x09c0022aU, 0x5a510800U},
    {0x09c62b00U, 0x5a4dc000U},
    {0x0a01031bU, 0x5a345000U},
    {0x0a2c6410U, 0x5a1bf800U},
    {0x0b4b1f30U, 0x598fb000U},
    {0x0b883a10U, 0x59782800U},
    {0x0bc4b258U, 0x594e8800U},
    {0x0c000200U, 0x59350000U},
    {0x0c000801U, 0x5934f800U},
    {0x0c004b10U, 0x5934d000U},
    {0x0c008804U, 0x5934a000U},
    {0x0c00a002U, 0x59349000U},
    {0x0c00a030U, 0x59349000U},
    {0x0c08c035U, 0x592f2000U},
    {0x0c0bd0a1U, 0x592d3000U},
    {0x0c800491U, 0x58fff800U},
    {0x0c820010U, 0x58fe0000U},
    {0x0c880d80U, 0x58f85000U},
    {0x0ccf54cdU, 0x58c92800U},
    {0x0d101084U, 0x58aaa000U},
    {0x0da59eceU, 0x58611000U},
    {0x0dc4340dU, 0x584ec800U},
    {0x0ea4a816U, 0x57e1b800U},
    {0x0ec9c371U, 0x57cbe800U},
    {0x10000000U, 0x57350000U},
    {0x10000004U, 0x57350000U},
    {0x10000008U, 0x57350000U},
    {0x1000000cU, 0x57350000U},
    {0x10000010U, 0x57350000U},
    {0x10000800U, 0x5734f800U},
    {0x10001002U, 0x5734f800U},
    {0x10001420U, 0x5734f800U},
    {0x10002100U, 0x5734e800U},
    {0x10003060U, 0x5734e000U},
    {0x10008041U, 0x5734a800U},
    {0x1000a008U, 0x57349000U},
    {0x10020000U, 0x57339800U},
    {0x10022200U, 0x57338000U},
    {0x1002c00cU, 0x57332000U},
    {0x10041810U, 0x57323000U},
    {0x10042100U, 0x57322800U},
    {0x10050301U, 0x57319800U},
    {0x10080000U, 0x572f9800U},
    {0x10080424U, 0x572f9800U},
    {0x10084054U, 0x572f7000U},
    {0x10085080U, 0x572f6800U},
    {0x100a0000U, 0x572e5000U},
    {0x100c0000U, 0x572d1000U},
    {0x100c1100U, 0x572d0800U},
    {0x1010d020U, 0x572a2800U},
    {0x10117202U, 0x5729d000U},
    {0x10200233U, 0x5721e800U},
    {0x10204100U, 0x5721c800U},
    {0x1020453dU, 0x5721c800U},
    {0x10220302U, 0x5720e800U},
    {0x1028c844U, 0x571da800U},
    {0x10400800U, 0x5713c800U},
    {0x104024b0U, 0x5713c000U},
    {0x10458001U, 0x5711b800U},
    {0x104c8020U, 0x570f3800U},
    {0x1071e538U, 0x5703b000U},
    {0x1073c862U, 0x57033000U},
    {0x10801000U, 0x56ffe800U},
    {0x10808014U, 0x56ff7800U},
    {0x108080c8U, 0x56ff7800U},
    {0x11000000U, 0x56b50000U},
    {0x1105218cU, 0x56b18000U},
    {0x110a1106U, 0x56ae4800U},
    {0x112865e1U, 0x569dd000U},
    {0x11419d02U, 0x56933000U},
    {0x116113a4U, 0x56888800U},
    {0x119c1481U, 0x5667d000U},
    {0x11c15411U, 0x56505000U},
    {0x11f81766U, 0x5637e800U},
    {0x1200060cU, 0x56350000U},
    {0x1204080aU, 0x56323800U},
    {0x12080400U, 0x562f9800U},
    {0x124149ccU, 0x56135000U},
    {0x12429902U, 0x5612d000U},
    {0x12808105U, 0x55ff7800U},
    {0x12853ac1U, 0x55fae800U},
    {0x129ca5efU, 0x55e76800U},
    {0x1308c012U, 0x55af2000U},
    {0x140104b0U, 0x55345000U},
    {0x14102000U, 0x552a9800U},
    {0x1441b50eU, 0x55132800U},
    {0x14441103U, 0x55124800U},
    {0x144a3a29U, 0x55100800U},
    {0x144c01d0U, 0x550f6000U},
    {0x145e10b0U, 0x55097000U},
    {0x14630102U, 0x5507e800U},
    {0x146cd792U, 0x55051000U},
    {0x1482c881U, 0x54fd4000U},
    {0x148d2081U, 0x54f3d000U},
    {0x149598e4U, 0x54ecd000U},
    {0x15044000U, 0x54b21800U},
    {0x15c022d8U, 0x5450f800U},
    {0x16040002U, 0x54324000U},
    {0x160a2902U, 0x542e3800U},
    {0x166e8bf3U, 0x54049800U},
    {0x16828144U, 0x53fd8000U},
    {0x17021c04U, 0x53b38800U},
    {0x17161804U, 0x53a72800U},
    {0x1800020aU, 0x53350000U},
    {0x18003080U, 0x5334e000U},
    {0x18140a21U, 0x53285800U},
    {0x18162483U, 0x53272800U},
    {0x18301193U, 0x531a5800U},
    {0x1834226dU, 0x53189800U},
    {0x18713eb2U, 0x5303d800U},
    {0x18c06e88U, 0x52d0d000U},
    {0x19061819U, 0x52b0d800U},
    {0x199dc416U, 0x52669800U},
    {0x1a0a3805U, 0x522e3000U},
    {0x1a280000U, 0x521e0000U},
    {0x1b8f0828U, 0x51722800U},
    {0x1c0c120aU, 0x512d0800U},
    {0x1c2448e3U, 0x511fc800U},
    {0x1d000384U, 0x50b50000U},
    {0x1d805309U, 0x507fb000U},
    {0x1d920d43U, 0x506fa800U},
    {0x1f9000f4U, 0x4f715800U},
    {0x20000000U, 0x4f350000U},
    {0x20000001U, 0x4f350000U},
    {0x20000004U, 0x4f350000U},
    {0x20000020U, 0x4f350000U},
    {0x20000022U, 0x4f350000U},
    {0x20000100U, 0x4f350000U},
    {0x20000210U, 0x4f350000U},
    {0x20000458U, 0x4f350000U},
    {0x20000804U, 0x4f34f800U},
    {0x20001000U, 0x4f34f800U},
    {0x20001008U, 0x4f34f800U},
    {0x20002000U, 0x4f34e800U},
    {0x20002004U, 0x4f34e800U},
    {0x20002154U, 0x4f34e800U},
    {0x20008020U, 0x4f34a800U},
    {0x20014128U, 0x4f342800U},
    {0x20028531U, 0x4f334800U},
    {0x20030000U, 0x4f32f000U},
    {0x200400c2U, 0x4f324000U},
    {0x20040c16U, 0x4f323800U},
    {0x20043702U, 0x4f322000U},
    {0x20080000U, 0x4f2f9800U},
    {0x20080040U, 0x4f2f9800U},
    {0x200805c0U, 0x4f2f9800U},
    {0x20081826U, 0x4f2f8800U},
    {0x20090004U, 0x4f2ef800U},
    {0x20120061U, 0x4f297800U},
    {0x20144844U, 0x4f283000U},
    {0x20200017U, 0x4f21e800U},
    {0x20221800U, 0x4f20e000U},
    {0x20224c92U, 0x4f20c800U},
    {0x20281011U, 0x4f1df800U},
    {0x202a0000U, 0x4f1d1000U},
    {0x202c2072U, 0x4f1c1800U},
    {0x20400002U, 0x4f13c800U},
    {0x20400100U, 0x4f13c800U},
    {0x20408000U, 0x4f139800U},
    {0x20443c50U, 0x4f123800U},
    {0x20494018U, 0x4f105800U},
    {0x20509aa5U, 0x4f0dd000U},
    {0x20510000U, 0x4f0da800U},
    {0x20540200U, 0x4f0ca800U},
    {0x20541600U, 0x4f0ca000U},
    {0x205571e8U, 0x4f0c2800U},
    {0x20589c18U, 0x4f0b2800U},
    {0x206201b8U, 0x4f083800U},
    {0x20821000U, 0x4efdf000U},
    {0x20a6d85aU, 0x4ee03800U},
    {0x20c21040U, 0x4ecfe800U},
    {0x20e40100U, 0x4ebfd000U},
    {0x20f73218U, 0x4eb83800U},
    {0x21006200U, 0x4eb4c000U},
    {0x2100de98U, 0x4eb47000U},
    {0x21010001U, 0x4eb45000U},
    {0x21050291U, 0x4eb19800U},
    {0x21a488c3U, 0x4e61d000U},
    {0x22000000U, 0x4e350000U},
    {0x22005001U, 0x4e34c800U},
    {0x2202a805U, 0x4e333000U},
    {0x22105800U, 0x4e2a7800U},
    {0x22108072U, 0x4e2a5800U},
    {0x22130294U, 0x4e28e800U},
    {0x222083a8U, 0x4e21a800U},
    {0x22221a39U, 0x4e20e000U},
    {0x2264030aU, 0x4e07a000U},
    {0x2284f88bU, 0x4dfb2800U},
    {0x22ed5c10U, 0x4dbc0000U},
    {0x23095000U, 0x4daec800U},
    {0x2334f619U, 0x4d984000U},
    {0x23b0ca02U, 0x4d59d800U},
    {0x24000000U, 0x4d350000U},
    {0x24002008U, 0x4d34e800U},
    {0x24008845U, 0x4d34a000U},
    {0x24050004U, 0x4d319800U},
    {0x24404000U, 0x4d13b000U},
    {0x246ca10aU, 0x4d052000U},
    {0x248202b1U, 0x4cfe0000U},
    {0x24841000U, 0x4cfc0000U},
    {0x24a80000U, 0x4cdf7000U},
    {0x24d80000U, 0x4cc51000U},
    {0x25140400U, 0x4ca85800U},
    {0x2546254aU, 0x4c918000U},
    {0x25a68224U, 0x4c607000U},
    {0x2601dac4U, 0x4c33b800U},
    {0x266a9253U, 0x4c05b800U},
    {0x269886d0U, 0x4bea8800U},
    {0x26b41198U, 0x4bd7d800U},
    {0x28042000U, 0x4b322800U},
    {0x28110000U, 0x4b2a1000U},
    {0x2818469cU, 0x4b25f800U},
    {0x28288491U, 0x4b1dc800U},
    {0x28a90090U, 0x4adec800U},
    {0x29122122U, 0x4aa96800U},
    {0x29146090U, 0x4aa82000U},
    {0x29805c08U, 0x4a7fa800U},
    {0x2a880242U, 0x49f85800U},
    {0x2b0043f0U, 0x49b4d800U},
    {0x2c008390U, 0x4934a800U},
    {0x2c9a7302U, 0x48e91000U},
    {0x2ca88009U, 0x48df2000U},
    {0x2e31e50dU, 0x48199000U},
    {0x2ea05031U, 0x47e4b800U},
    {0x30000408U, 0x47350000U},
    {0x30100044U, 0x472aa800U},
    {0x301ac04dU, 0x4724a000U},
    {0x3031a2b8U, 0x4719a800U},
    {0x30420000U, 0x47130800U},
    {0x30521481U, 0x470d4800U},
    {0x306e2854U, 0x4704b800U},
    {0x30830004U, 0x46fd0800U},
    {0x31024101U, 0x46b37000U},
    {0x310c112cU, 0x46ad0800U},
    {0x3120c0a6U, 0x46a18800U},
    {0x31521230U, 0x468d4800U},
    {0x31981cf3U, 0x466ad800U},
    {0x31a43b91U, 0x46620000U},
    {0x3220fa80U, 0x46217000U},
    {0x325613d6U, 0x460bf800U},
    {0x32573587U, 0x460ba000U},
    {0x329080a0U, 0x45f0f000U},
    {0x33180875U, 0x45a61800U},
    {0x33903c21U, 0x45712800U},
    {0x34080000U, 0x452f9800U},
    {0x34800000U, 0x44fff800U},
    {0x3480a6b0U, 0x44ff5800U},
    {0x35400000U, 0x4493c800U},
    {0x354d0018U, 0x448f0800U},
    {0x36906805U, 0x43f10000U},
    {0x38224400U, 0x4320c800U},
    {0x3932f407U, 0x42991800U},
    {0x3952908cU, 0x428d2000U},
    {0x39890c09U, 0x42776800U},
    {0x3a903308U, 0x41f13000U},
    {0x3c1c9900U, 0x4123a800U},
    {0x40000000U, 0x3f350000U},
    {0x40000400U, 0x3f350000U},
    {0x40000800U, 0x3f34f800U},
    {0x40001000U, 0x3f34f800U},
    {0x40001100U, 0x3f34f800U},
    {0x40008000U, 0x3f34a800U},
    {0x40041254U, 0x3f323800U},
    {0x40049010U, 0x3f31e000U},
    {0x40080041U, 0x3f2f9800U},
    {0x4008d459U, 0x3f2f1800U},
    {0x40200080U, 0x3f21e800U},
    {0x40240060U, 0x3f1fe800U},
    {0x402da820U, 0x3f1b6800U},
    {0x4031c002U, 0x3f19a000U},
    {0x40388500U, 0x3f16c800U},
    {0x40400000U, 0x3f13c800U},
    {0x40408000U, 0x3f139800U},
    {0x40410101U, 0x3f136800U},
    {0x40420500U, 0x3f130800U},
    {0x40440003U, 0x3f124800U},
    {0x4045c89dU, 0x3f11a000U},
    {0x404a6080U, 0x3f0ff800U},
    {0x4076024cU, 0x3f029000U},
    {0x40800000U, 0x3efff800U},
    {0x40800007U, 0x3efff800U},
    {0x4080067aU, 0x3efff800U},
    {0x40808000U, 0x3eff7800U},
    {0x40840081U, 0x3efc1000U},
    {0x41000800U, 0x3eb4f800U},
    {0x41080080U, 0x3eaf9800U},
    {0x41100800U, 0x3eaaa800U},
    {0x41113000U, 0x3ea9f800U},
    {0x41190814U, 0x3ea59000U},
    {0x4181f31fU, 0x3e7e1800U},
    {0x41910125U, 0x3e708000U},
    {0x41b01600U, 0x3e5a4800U},
    {0x41d2e02fU, 0x3e477800U},
    {0x42008200U, 0x3e34a800U},
    {0x42008500U, 0x3e34a800U},
    {0x4200c100U, 0x3e348000U},
    {0x4220014cU, 0x3e21e800U},
    {0x42214200U, 0x3e214800U},
    {0x42800514U, 0x3dfff800U},
    {0x42a8002aU, 0x3ddf7000U},
    {0x43213129U, 0x3da15000U},
    {0x43c02200U, 0x3d50f800U},
    {0x44001004U, 0x3d34f800U},
    {0x440cd1c4U, 0x3d2c9800U},
    {0x44139791U, 0x3d289800U},
    {0x44200410U, 0x3d21e800U},
    {0x442bbfa2U, 0x3d1c4800U},
    {0x444c0280U, 0x3d0f6000U},
    {0x4452ff80U, 0x3d0d0000U},
    {0x4495e594U, 0x3cec9000U},
    {0x44b91a74U, 0x3cd4e800U},
    {0x450a2972U, 0x3cae3800U},
    {0x4518c051U, 0x3ca5b800U},
    {0x45230053U, 0x3ca06800U},
    {0x45431a2eU, 0x3c92a000U},
    {0x458007c0U, 0x3c7ff800U},
    {0x46003001U, 0x3c34e000U},
    {0x46010080U, 0x3c345000U},
    {0x46086825U, 0x3c2f5800U},
    {0x462f8ea8U, 0x3c1a9000U},
    {0x465a4520U, 0x3c0aa000U},
    {0x468e1f00U, 0x3bf2f000U},
    {0x469e8d12U, 0x3be60800U},
    {0x46d34bf0U, 0x3bc74000U},
    {0x47073fa0U, 0x3bb01800U},
    {0x4717d544U, 0x3ba63000U},
    {0x4742b154U, 0x3b92c800U},
    {0x474de6c8U, 0x3b8eb800U},
    {0x474ef708U, 0x3b8e5800U},
    {0x47569714U, 0x3b8bd000U},
    {0x47968210U, 0x3b6c1800U},
    {0x479b09ecU, 0x3b689800U},
    {0x47be311aU, 0x3b520000U},
    {0x4804c0a6U, 0x3b31c000U},
    {0x4805b924U, 0x3b311800U},
    {0x4848ea52U, 0x3b108000U},
    {0x48557a98U, 0x3b0c2800U},
    {0x4856e526U, 0x3b0bb800U},
    {0x48700101U, 0x3b043000U},
    {0x48881100U, 0x3af84800U},
    {0x4904584bU, 0x3ab20800U},
    {0x49100013U, 0x3aaaa800U},
    {0x49112891U, 0x3aa9f800U},
    {0x49200688U, 0x3aa1e800U},
    {0x4a115602U, 0x3a29e000U},
    {0x4ab05000U, 0x39da2000U},
    {0x4aeb2901U, 0x39bce000U},
    {0x4c110029U, 0x392a1000U},
    {0x4d92c605U, 0x386f1800U},
    {0x4dd0a4d4U, 0x38488000U},
    {0x4e4c3003U, 0x380f5000U},
    {0x50000c14U, 0x3734f800U},
    {0x50004000U, 0x3734d800U},
    {0x50040202U, 0x37324000U},
    {0x50145000U, 0x37282800U},
    {0x5022720bU, 0x3720b000U},
    {0x50388ca0U, 0x3716c800U},
    {0x5040130bU, 0x3713c800U},
    {0x51000010U, 0x36b50000U},
    {0x51150080U, 0x36a7c800U},
    {0x514cba79U, 0x368f2800U},
    {0x51a0c124U, 0x36647000U},
    {0x51b03460U, 0x365a3800U},
    {0x52018421U, 0x3633f000U},
    {0x52243ae0U, 0x361fd000U},
    {0x5224c00eU, 0x361f8800U},
    {0x5258da01U, 0x360b1000U},
    {0x53004280U, 0x35b4d800U},
    {0x540903a1U, 0x352ef800U},
    {0x54c5d086U, 0x34cdf000U},
    {0x55555555U, 0x348c3800U},
    {0x555680fcU, 0x348bd800U},
    {0x56460991U, 0x34118800U},
    {0x57d43f04U, 0x3346d000U},
    {0x57eabaa7U, 0x333d0800U},
    {0x580aa2e0U, 0x332df000U},
    {0x58108041U, 0x332a5800U},
    {0x58403a04U, 0x3313b800U},
    {0x5910906fU, 0x32aa5000U},
    {0x59c04c93U, 0x3250e000U},
    {0x5a022394U, 0x32338000U},
    {0x5a1cb150U, 0x3223a000U},
    {0x5a960451U, 0x31ec7800U},
    {0x5c02d321U, 0x31331000U},
    {0x5cb431ddU, 0x30d7c800U},
    {0x5e0fadd4U, 0x302ae000U},
    {0x5eb17094U, 0x2fd97000U},
    {0x60000402U, 0x2f350000U},
    {0x600a9f52U, 0x2f2df000U},
    {0x60100400U, 0x2f2aa800U},
    {0x60110061U, 0x2f2a1000U},
    {0x601c0104U, 0x2f23f800U},
    {0x60200020U, 0x2f21e800U},
    {0x60320744U, 0x2f198000U},
    {0x60c9a912U, 0x2ecbf800U},
    {0x610406a1U, 0x2eb24000U},
    {0x610b5909U, 0x2ead7800U},
    {0x6110052eU, 0x2eaaa800U},
    {0x6184d014U, 0x2e7b5000U},
    {0x61daec82U, 0x2e43c000U},
    {0x62043040U, 0x2e322000U},
    {0x62080000U, 0x2e2f9800U},
    {0x620c2501U, 0x2e2d0000U},
    {0x625021ddU, 0x2e0df800U},
    {0x62b03f18U, 0x2dda3000U},
    {0x62e40552U, 0x2dbfd000U},
    {0x62ea3a53U, 0x2dbd4000U},
    {0x64000090U, 0x2d350000U},
    {0x64008049U, 0x2d34a800U},
    {0x658828a8U, 0x2c783800U},
    {0x663e98c0U, 0x2c145800U},
    {0x68220450U, 0x2b20e800U},
    {0x682c1800U, 0x2b1c2000U},
    {0x68602800U, 0x2b08c800U},
    {0x68699d49U, 0x2b060000U},
    {0x68863910U, 0x2af9f800U},
    {0x6a942888U, 0x29edf000U},
    {0x6bf090b8U, 0x293ab800U},
    {0x6e8ee009U, 0x27f25000U},
    {0x6ef38037U, 0x27b99800U},
    {0x70008028U, 0x2734a800U},
    {0x7062d8b9U, 0x2707f800U},
    {0x70829c00U, 0x26fd6800U},
    {0x72000780U, 0x26350000U},
    {0x7341161fU, 0x25936800U},
    {0x74d9ccacU, 0x24c44800U},
    {0x76100000U, 0x242aa800U},
    {0x7a5bf232U, 0x220a1800U},
    {0x7b120361U, 0x21a97800U},
    {0x7c00a28aU, 0x21349000U},
    {0x7c400500U, 0x2113c800U},
    {0x7ca80405U, 0x20df7000U},
    {0x7ffffffdU, 0x7ffffffdU},
    {0x80000000U, 0xff800000U},
    {0x80000011U, 0xff800000U},
    {0x80000022U, 0xff800000U},
    {0x80000420U, 0xff800000U},
    {0x80000430U, 0xff800000U},
    {0x80000800U, 0xff800000U},
    {0x80001100U, 0xff800000U},
    {0x80001810U, 0xff800000U},
    {0x80008100U, 0xff800000U},
    {0x8000cc30U, 0xff800000U},
    {0x80020900U, 0xff800000U},
    {0x80042000U, 0xff800000U},
    {0x80080010U, 0xff800000U},
    {0x80080514U, 0xff800000U},
    {0x80090002U, 0xff800000U},
    {0x80110e00U, 0xff800000U},
    {0x80118809U, 0xff800000U},
    {0x80160441U, 0xff800000U},
    {0x80210000U, 0xff800000U},
    {0x80222b84U, 0xff800000U},
    {0x80246022U, 0xff800000U},
    {0x8035bd1bU, 0xff800000U},
    {0x80381a21U, 0xff800000U},
    {0x804360a4U, 0xff800000U},
    {0x80500001U, 0xff800000U},
    {0x80602000U, 0xff800000U},
    {0x806828e4U, 0xff800000U},
    {0x80800012U, 0xffc00000U},
    {0x80a44314U, 0xffc00000U},
    {0x80a630a0U, 0xffc00000U},
    {0x80b00000U, 0xffc00000U},
    {0x80c738d3U, 0xffc00000U},
    {0x80c81200U, 0xffc00000U},
    {0x81000001U, 0xffc00000U},
    {0x81002000U, 0xffc00000U},
    {0x81040008U, 0xffc00000U},
    {0x81041302U, 0xffc00000U},
    {0x81046203U, 0xffc00000U},
    {0x81080498U, 0xffc00000U},
    {0x81121016U, 0xffc00000U},
    {0x81206100U, 0xffc00000U},
    {0x81335c00U, 0xffc00000U},
    {0x81401040U, 0xffc00000U},
    {0x8170b430U, 0xffc00000U},
    {0x82000020U, 0xffc00000U},
    {0x820001a2U, 0xffc00000U},
    {0x82000500U, 0xffc00000U},
    {0x82020000U, 0xffc00000U},
    {0x82024204U, 0xffc00000U},
    {0x82046189U, 0xffc00000U},
    {0x82224259U, 0xffc00000U},
    {0x82480048U, 0xffc00000U},
    {0x82482001U, 0xffc00000U},
    {0x824fea11U, 0xffc00000U},
    {0x82534631U, 0xffc00000U},
    {0x83028a85U, 0xffc00000U},
    {0x8341c268U, 0xffc00000U},
    {0x83434ac3U, 0xffc00000U},
    {0x83b53a20U, 0xffc00000U},
    {0x84000000U, 0xffc00000U},
    {0x84000104U, 0xffc00000U},
    {0x84600002U, 0xffc00000U},
    {0x846e0224U, 0xffc00000U},
    {0x848a8380U, 0xffc00000U},
    {0x85005545U, 0xffc00000U},
    {0x850a1c69U, 0xffc00000U},
    {0x85105c00U, 0xffc00000U},
    {0x8534008cU, 0xffc00000U},
    {0x854c2226U, 0xffc00000U},
    {0x85a22a0bU, 0xffc00000U},
    {0x85a50980U, 0xffc00000U},
    {0x86000100U, 0xffc00000U},
    {0x87545018U, 0xffc00000U},
    {0x87e5c03dU, 0xffc00000U},
    {0x88000020U, 0xffc00000U},
    {0x88060454U, 0xffc00000U},
    {0x88092820U, 0xffc00000U},
    {0x8809e100U, 0xffc00000U},
    {0x8818105cU, 0xffc00000U},
    {0x88204000U, 0xffc00000U},
    {0x88208a04U, 0xffc00000U},
    {0x88218403U, 0xffc00000U},
    {0x883ce190U, 0xffc00000U},
    {0x8841a008U, 0xffc00000U},
    {0x8842221cU, 0xffc00000U},
    {0x88725568U, 0xffc00000U},
    {0x88800000U, 0xffc00000U},
    {0x88900289U, 0xffc00000U},
    {0x8a010180U, 0xffc00000U},
    {0x8a652cd8U, 0xffc00000U},
    {0x8c00024aU, 0xffc00000U},
    {0x8c080628U, 0xffc00000U},
    {0x8c41f9d4U, 0xffc00000U},
    {0x8c7e0a57U, 0xffc00000U},
    {0x8e1982c0U, 0xffc00000U},
    {0x8e5660a9U, 0xffc00000U},
    {0x8e844b41U, 0xffc00000U},
    {0x8f14121aU, 0xffc00000U},
    {0x90000000U, 0xffc00000U},
    {0x90000100U, 0xffc00000U},
    {0x90020000U, 0xffc00000U},
    {0x90041001U, 0xffc00000U},
    {0x900804e3U, 0xffc00000U},
    {0x901115f4U, 0xffc00000U},
    {0x903749a1U, 0xffc00000U},
    {0x903b0636U, 0xffc00000U},
    {0x9043d498U, 0xffc00000U},
    {0x9058260dU, 0xffc00000U},
    {0x90791448U, 0xffc00000U},
    {0x90e4e188U, 0xffc00000U},
    {0x9200802cU, 0xffc00000U},
    {0x92022048U, 0xffc00000U},
    {0x93511200U, 0xffc00000U},
    {0x940b0024U, 0xffc00000U},
    {0x95000831U, 0xffc00000U},
    {0x96224385U, 0xffc00000U},
    {0x97186d50U, 0xffc00000U},
    {0x9761f469U, 0xffc00000U},
    {0x9808210aU, 0xffc00000U},
    {0x98420204U, 0xffc00000U},
    {0x990c7a65U, 0xffc00000U},
    {0x9af96125U, 0xffc00000U},
    {0x9bd48a8cU, 0xffc00000U},
    {0x9c066281U, 0xffc00000U},
    {0x9f423b67U, 0xffc00000U},
    {0xa0000080U, 0xffc00000U},
    {0xa0004d36U, 0xffc00000U},
    {0xa0060090U, 0xffc00000U},
    {0xa0120c1dU, 0xffc00000U},
    {0xa0a10114U, 0xffc00000U},
    {0xa1010a82U, 0xffc00000U},
    {0xa167a168U, 0xffc00000U},
    {0xa1a4428aU, 0xffc00000U},
    {0xa34d1603U, 0xffc00000U},
    {0xa3810d34U, 0xffc00000U},
    {0xa3e0a303U, 0xffc00000U},
    {0xa4000000U, 0xffc00000U},
    {0xa4004220U, 0xffc00000U},
    {0xa4208042U, 0xffc00000U},
    {0xa4522485U, 0xffc00000U},
    {0xa5007b09U, 0xffc00000U},
    {0xa51076b9U, 0xffc00000U},
    {0xa61008e2U, 0xffc00000U},
    {0xa81594c0U, 0xffc00000U},
    {0xa928c801U, 0xffc00000U},
    {0xa9812b32U, 0xffc00000U},
    {0xaa8010b9U, 0xffc00000U},
    {0xaab19f65U, 0xffc00000U},
    {0xab087290U, 0xffc00000U},
    {0xacb11007U, 0xffc00000U},
    {0xb0018200U, 0xffc00000U},
    {0xb0244201U, 0xffc00000U},
    {0xb0502444U, 0xffc00000U},
    {0xb081a030U, 0xffc00000U},
    {0xb082514bU, 0xffc00000U},
    {0xb0880b8cU, 0xffc00000U},
    {0xb121aa08U, 0xffc00000U},
    {0xb2b42a00U, 0xffc00000U},
    {0xb42616aaU, 0xffc00000U},
    {0xb5c213c6U, 0xffc00000U},
    {0xb811911aU, 0xffc00000U},
    {0xb854a312U, 0xffc00000U},
    {0xb8c20860U, 0xffc00000U},
    {0xb8c734c1U, 0xffc00000U},
    {0xb984c401U, 0xffc00000U},
    {0xba00052cU, 0xffc00000U},
    {0xba104094U, 0xffc00000U},
    {0xbaf89b80U, 0xffc00000U},
    {0xc0000900U, 0xffc00000U},
    {0xc0004041U, 0xffc00000U},
    {0xc0229488U, 0xffc00000U},
    {0xc0404200U, 0xffc00000U},
    {0xc04b6c89U, 0xffc00000U},
    {0xc13df120U, 0xffc00000U},
    {0xc14121e9U, 0xffc00000U},
    {0xc174d268U, 0xffc00000U},
    {0xc2675ce0U, 0xffc00000U},
    {0xc41a1208U, 0xffc00000U},
    {0xc4400120U, 0xffc00000U},
    {0xc4715a48U, 0xffc00000U},
    {0xc4a972c0U, 0xffc00000U},
    {0xc5445b42U, 0xffc00000U},
    {0xc5dc34c0U, 0xffc00000U},
    {0xc6000220U, 0xffc00000U},
    {0xc6a47e00U, 0xffc00000U},
    {0xc6c8b10cU, 0xffc00000U},
    {0xc6d8d428U, 0xffc00000U},
    {0xc7381e31U, 0xffc00000U},
    {0xc73a1c91U, 0xffc00000U},
    {0xc7513b8cU, 0xffc00000U},
    {0xc77a42dbU, 0xffc00000U},
    {0xc79bd335U, 0xffc00000U},
    {0xc79e7eb4U, 0xffc00000U},
    {0xc7a05e46U, 0xffc00000U},
    {0xc7bbaf64U, 0xffc00000U},
    {0xc838e801U, 0xffc00000U},
    {0xc8470004U, 0xffc00000U},
    {0xc92689c8U, 0xffc00000U},
    {0xc9e50548U, 0xffc00000U},
    {0xcbb0196bU, 0xffc00000U},
    {0xcc004900U, 0xffc00000U},
    {0xcc418b66U, 0xffc00000U},
    {0xce25a888U, 0xffc00000U},
    {0xd160c617U, 0xffc00000U},
    {0xd2880b00U, 0xffc00000U},
    {0xd2c20680U, 0xffc00000U},
    {0xd3420001U, 0xffc00000U},
    {0xd48e6d38U, 0xffc00000U},
    {0xd4fba154U, 0xffc00000U},
    {0xd6461568U, 0xffc00000U},
    {0xd6545804U, 0xffc00000U},
    {0xd882b440U, 0xffc00000U},
    {0xda2c1324U, 0xffc00000U},
    {0xdc730407U, 0xffc00000U},
    {0xdcd9da47U, 0xffc00000U},
    {0xdf97008cU, 0xffc00000U},
    {0xe0000243U, 0xffc00000U},
    {0xe0020616U, 0xffc00000U},
    {0xe10a8ab2U, 0xffc00000U},
    {0xe38e1853U, 0xffc00000U},
    {0xe43b01d1U, 0xffc00000U},
    {0xe5891204U, 0xffc00000U},
    {0xe8218900U, 0xffc00000U},
    {0xe8540142U, 0xffc00000U},
    {0xea020000U, 0xffc00000U},
    {0xebcbf061U, 0xffc00000U},
    {0xec3814bdU, 0xffc00000U},
    {0xed8560c8U, 0xffc00000U},
    {0xee1a0055U, 0xffc00000U},
    {0xee838919U, 0xffc00000U},
    {0xef21da5fU, 0xffc00000U},
    {0xf3171f6bU, 0xffc00000U},
    {0xf9d05bb6U, 0xffc00000U},
    {0xfa4c074cU, 0xffc00000U},
    {0xfe8cc419U, 0xffc00000U},
    {0xff8000ffU, 0xffc000ffU},
    {0xfffffffeU, 0xfffffffeU},
    {0xffffffffU, 0xffffffffU},
};


ALWAYS_INLINE static uint32_t Float32Bits(float32_t value) {
  return reinterpret_cast<uint32_t &>(value);
}

ALWAYS_INLINE static float32_t Float32FromBits(uint32_t bits) {
  return reinterpret_cast<float32_t &>(bits);
}

template <std::size_t kNumEntries>
ALWAYS_INLINE static bool LookupApprox32(const ApproxFpPair (&table)[kNumEntries],
                                         uint32_t input, uint32_t &output) {
  std::size_t low = 0;
  std::size_t high = kNumEntries;
  while (low < high) {
    const auto mid = low + ((high - low) / 2);
    const auto key = table[mid].input;
    if (input == key) {
      output = table[mid].output;
      return true;
    } else if (input < key) {
      high = mid;
    } else {
      low = mid + 1;
    }
  }
  return false;
}

DEF_HELPER(ApproximateRcp32, float32_t src_float)->float32_t {
  const auto bits = Float32Bits(src_float);
  uint32_t mapped = 0;
  if (LookupApprox32(kApproxRcp32Table, bits, mapped)) {
    return Float32FromBits(mapped);
  }
  return FDiv(1.0f, src_float);
}

DEF_HELPER(ApproximateRsqrt32, float32_t src_float)->float32_t {
  const auto bits = Float32Bits(src_float);
  uint32_t mapped = 0;
  if (LookupApprox32(kApproxRsqrt32Table, bits, mapped)) {
    return Float32FromBits(mapped);
  }
  return FDiv(1.0f, SquareRoot32(memory, state, src_float));
}

template <typename D, typename S1, typename S2>
DEF_SEM(SQRTSS, D dst, S1 src1, S2 src2) {

  // Extract a "single-precision" (32-bit) float from [31:0] of src2 vector:
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
DEF_SEM(RSQRTSS, D dst, S1 src1, S2 src2) {

  // Extract a "single-precision" (32-bit) float from [31:0] of src2 vector:
  auto src_float = FExtractV32(FReadV32(src2), 0);

  // Initialize dest vector, while also copying src1[127:32] -> dst[127:32].
  auto temp_vec = FReadV32(src1);

  // Store the approximate reciprocal square root result in dest[31:0].
  temp_vec = FInsertV32(temp_vec, 0,
                       ApproximateRsqrt32(memory, state, src_float));

  // Write out the result and return memory state:
  FWriteV32(dst, temp_vec);  // SSE: Writes to XMM, AVX: Zero-extends XMM.
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(RCPSS, D dst, S1 src1, S2 src2) {

  // Extract a "single-precision" (32-bit) float from [31:0] of src2 vector:
  auto src_float = FExtractV32(FReadV32(src2), 0);

  // Initialize dest vector, while also copying src1[127:32] -> dst[127:32].
  auto temp_vec = FReadV32(src1);

  // Store the approximate reciprocal result in dest[31:0].
  temp_vec = FInsertV32(temp_vec, 0,
                       ApproximateRcp32(memory, state, src_float));

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

  // Store the approximate reciprocal square root result in dest[31:0].
  temp_vec = FInsertV32(temp_vec, 0,
                       ApproximateRsqrt32(memory, state, src_float));

  // Write out the result and return memory state:
  FWriteV32(dst, temp_vec);  // SSE: Writes to XMM, AVX: Zero-extends XMM.
  return memory;
}
#endif  // HAS_FEATURE_AVX
}  // namespace

DEF_ISEL(SQRTSS_XMMss_MEMss) = SQRTSS<V128W, V128, MV32>;
DEF_ISEL(SQRTSS_XMMss_XMMss) = SQRTSS<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VSQRTSS_XMMdq_XMMdq_MEMd) = VSQRTSS<VV128W, V128, MV32>;)
IF_AVX(DEF_ISEL(VSQRTSS_XMMdq_XMMdq_XMMd) = VSQRTSS<VV128W, V128, V128>;)
/*
4316 VSQRTSS VSQRTSS_XMMf32_MASKmskw_XMMf32_XMMf32_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MASKOP_EVEX MXCSR SIMD_SCALAR
4317 VSQRTSS VSQRTSS_XMMf32_MASKmskw_XMMf32_XMMf32_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MASKOP_EVEX MXCSR SIMD_SCALAR
4318 VSQRTSS VSQRTSS_XMMf32_MASKmskw_XMMf32_MEMf32_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: DISP8_SCALAR MASKOP_EVEX MEMORY_FAULT_SUPPRESSION MXCSR SIMD_SCALAR
*/

DEF_ISEL(RSQRTSS_XMMss_MEMss) = RSQRTSS<V128W, V128, MV32>;
DEF_ISEL(RSQRTSS_XMMss_XMMss) = RSQRTSS<V128W, V128, V128>;
DEF_ISEL(RCPSS_XMMss_MEMss) = RCPSS<V128W, V128, MV32>;
DEF_ISEL(RCPSS_XMMss_XMMss) = RCPSS<V128W, V128, V128>;
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
      square_root = __builtin_sqrt(src_float);
    }
  }

  return square_root;
}

template <typename D, typename S1, typename S2>
DEF_SEM(SQRTSD, D dst, S1 src1, S2 src2) {

  // Extract a "double-precision" (64-bit) float from [63:0] of src2 vector:
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

DEF_ISEL(SQRTSD_XMMsd_MEMsd) = SQRTSD<V128W, V128, MV64>;
DEF_ISEL(SQRTSD_XMMsd_XMMsd) = SQRTSD<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VSQRTSD_XMMdq_XMMdq_MEMq) = VSQRTSD<VV128W, V128, MV64>;)
IF_AVX(DEF_ISEL(VSQRTSD_XMMdq_XMMdq_XMMq) = VSQRTSD<VV128W, V128, V128>;)
/*
4295 VSQRTSD VSQRTSD_XMMf64_MASKmskw_XMMf64_XMMf64_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MASKOP_EVEX MXCSR SIMD_SCALAR
4296 VSQRTSD VSQRTSD_XMMf64_MASKmskw_XMMf64_XMMf64_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: MASKOP_EVEX MXCSR SIMD_SCALAR
4297 VSQRTSD VSQRTSD_XMMf64_MASKmskw_XMMf64_MEMf64_AVX512 AVX512 AVX512EVEX AVX512F_SCALAR ATTRIBUTES: DISP8_SCALAR MASKOP_EVEX MEMORY_FAULT_SUPPRESSION MXCSR SIMD_SCALAR
*/

namespace {

template <typename D, typename S1>
DEF_SEM(SQRTPS, D dst, S1 src1) {
  auto src_vec = FReadV32(src1);
  auto dest_vec = FReadV32(dst);

  auto vec_count = NumVectorElems(src_vec);
  _Pragma("unroll") for (std::size_t i = 0; i < vec_count; i++) {
    auto square_root = SquareRoot32(memory, state, FExtractV32(src_vec, i));
    dest_vec = FInsertV32(dest_vec, i, square_root);
  }

  FWriteV32(dst, dest_vec);
  return memory;
}

template <typename D, typename S1>
DEF_SEM(RSQRTPS, D dst, S1 src1) {
  auto src_vec = FReadV32(src1);
  auto dest_vec = FReadV32(dst);

  auto vec_count = NumVectorElems(src_vec);
  _Pragma("unroll") for (std::size_t i = 0; i < vec_count; i++) {
    dest_vec = FInsertV32(
        dest_vec, i,
        ApproximateRsqrt32(memory, state, FExtractV32(src_vec, i)));
  }

  FWriteV32(dst, dest_vec);
  return memory;
}

template <typename D, typename S1>
DEF_SEM(RCPPS, D dst, S1 src1) {
  auto src_vec = FReadV32(src1);
  auto dest_vec = FReadV32(dst);

  auto vec_count = NumVectorElems(src_vec);
  _Pragma("unroll") for (std::size_t i = 0; i < vec_count; i++) {
    dest_vec = FInsertV32(dest_vec, i,
                          ApproximateRcp32(memory, state,
                                           FExtractV32(src_vec, i)));
  }

  FWriteV32(dst, dest_vec);
  return memory;
}

template <typename D, typename S1>
DEF_SEM(SQRTPD, D dst, S1 src1) {
  auto src_vec = FReadV64(src1);

  auto sqrt_0 = SquareRoot64(memory, state, FExtractV64(src_vec, 0));
  auto sqrt_1 = SquareRoot64(memory, state, FExtractV64(src_vec, 1));

  auto temp_vec = FReadV64(dst);
  temp_vec = FInsertV64(temp_vec, 0, sqrt_0);
  temp_vec = FInsertV64(temp_vec, 1, sqrt_1);

  FWriteV64(dst, temp_vec);
  return memory;
}

}  // namespace

DEF_ISEL(SQRTPS_XMMps_MEMps) = SQRTPS<V128W, MV128>;
DEF_ISEL(SQRTPS_XMMps_XMMps) = SQRTPS<V128W, V128>;
DEF_ISEL(RSQRTPS_XMMps_MEMps) = RSQRTPS<V128W, MV128>;
DEF_ISEL(RSQRTPS_XMMps_XMMps) = RSQRTPS<V128W, V128>;
DEF_ISEL(RCPPS_XMMps_MEMps) = RCPPS<V128W, MV128>;
DEF_ISEL(RCPPS_XMMps_XMMps) = RCPPS<V128W, V128>;

DEF_ISEL(SQRTPD_XMMpd_MEMpd) = SQRTPD<V128W, MV128>;
DEF_ISEL(SQRTPD_XMMpd_XMMpd) = SQRTPD<V128W, V128>;

namespace {

ALWAYS_INLINE static float32_t RoundByImm32(float32_t val, uint8_t imm) {
  auto mode = UAnd8(imm, 3_u8);
  if (UAnd8(imm, 4_u8) != 0_u8) {
    // The tester runs with the default MXCSR rounding control: nearest even.
    mode = 0_u8;
  }

  if (mode == 1_u8) {
    return FRoundToNegativeInfinity32(val);
  } else if (mode == 2_u8) {
    return FRoundToPositiveInfinity32(val);
  } else if (mode == 3_u8) {
    return FTruncTowardZero32(val);
  } else {
    return FRoundToNearestEven32(val);
  }
}

ALWAYS_INLINE static float64_t RoundByImm64(float64_t val, uint8_t imm) {
  auto mode = UAnd8(imm, 3_u8);
  if (UAnd8(imm, 4_u8) != 0_u8) {
    // The tester runs with the default MXCSR rounding control: nearest even.
    mode = 0_u8;
  }

  if (mode == 1_u8) {
    return FRoundToNegativeInfinity64(val);
  } else if (mode == 2_u8) {
    return FRoundToPositiveInfinity64(val);
  } else if (mode == 3_u8) {
    return FTruncTowardZero64(val);
  } else {
    return FRoundToNearestEven64(val);
  }
}

template <typename D, typename S1>
DEF_SEM(ROUNDPS, D dst, S1 src1, I8 src2) {
  auto src_vec = FReadV32(src1);
  auto dst_vec = FClearV32(FReadV32(dst));
  auto imm = Read(src2);

  auto vec_count = NumVectorElems(src_vec);
  _Pragma("unroll") for (std::size_t i = 0; i < vec_count; ++i) {
    dst_vec = FInsertV32(dst_vec, i,
                         RoundByImm32(FExtractV32(src_vec, i), imm));
  }

  FWriteV32(dst, dst_vec);
  return memory;
}

template <typename D, typename S1>
DEF_SEM(ROUNDPD, D dst, S1 src1, I8 src2) {
  auto src_vec = FReadV64(src1);
  auto dst_vec = FClearV64(FReadV64(dst));
  auto imm = Read(src2);

  auto vec_count = NumVectorElems(src_vec);
  _Pragma("unroll") for (std::size_t i = 0; i < vec_count; ++i) {
    dst_vec = FInsertV64(dst_vec, i,
                         RoundByImm64(FExtractV64(src_vec, i), imm));
  }

  FWriteV64(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(ROUNDSS, D dst, S1 src1, S2 src2, I8 src3) {
  auto dst_vec = FReadV32(src1);
  auto src2_vec = FReadV32(src2);
  auto imm = Read(src3);
  dst_vec = FInsertV32(dst_vec, 0,
                       RoundByImm32(FExtractV32(src2_vec, 0), imm));
  FWriteV32(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(ROUNDSD, D dst, S1 src1, S2 src2, I8 src3) {
  auto dst_vec = FReadV64(src1);
  auto src2_vec = FReadV64(src2);
  auto imm = Read(src3);
  dst_vec = FInsertV64(dst_vec, 0,
                       RoundByImm64(FExtractV64(src2_vec, 0), imm));
  FWriteV64(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(ROUNDPS_XMMps_XMMps_IMMb) = ROUNDPS<V128W, V128>;
DEF_ISEL(ROUNDPS_XMMps_MEMps_IMMb) = ROUNDPS<V128W, MV128>;

DEF_ISEL(ROUNDPD_XMMpd_XMMpd_IMMb) = ROUNDPD<V128W, V128>;
DEF_ISEL(ROUNDPD_XMMpd_MEMpd_IMMb) = ROUNDPD<V128W, MV128>;

DEF_ISEL(ROUNDSS_XMMd_XMMd_IMMb) = ROUNDSS<V128W, V128, V128>;
DEF_ISEL(ROUNDSS_XMMd_MEMd_IMMb) = ROUNDSS<V128W, V128, MV32>;

DEF_ISEL(ROUNDSD_XMMq_XMMq_IMMb) = ROUNDSD<V128W, V128, V128>;
DEF_ISEL(ROUNDSD_XMMq_MEMq_IMMb) = ROUNDSD<V128W, V128, MV64>;

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(DPPS, D dst, S1 src1, S2 src2, I8 src3) {
  auto src1_vec = FReadV32(src1);
  auto src2_vec = FReadV32(src2);
  auto imm = Read(src3);

  float32_t products[4] = {};
  _Pragma("unroll") for (std::size_t i = 0; i < 4; ++i) {
    auto bit = UAnd8(UShr8(imm, TruncTo<uint8_t>(i + 4)), 1_u8);
    auto product = FMul(FExtractV32(src1_vec, i), FExtractV32(src2_vec, i));
    products[i] = Select<float32_t>(bit != 0_u8, product, 0.0f);
  }

  auto low_sum = FAdd(products[0], products[1]);
  auto high_sum = FAdd(products[2], products[3]);
  auto dot = FAdd(low_sum, high_sum);
  auto dst_vec = FClearV32(FReadV32(dst));
  _Pragma("unroll") for (std::size_t i = 0; i < 4; ++i) {
    auto bit = UAnd8(UShr8(imm, TruncTo<uint8_t>(i)), 1_u8);
    dst_vec = FInsertV32(dst_vec, i,
                         Select<float32_t>(bit != 0_u8, dot, 0.0f));
  }

  FWriteV32(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(DPPD, D dst, S1 src1, S2 src2, I8 src3) {
  auto src1_vec = FReadV64(src1);
  auto src2_vec = FReadV64(src2);
  auto imm = Read(src3);

  auto bit0 = UAnd8(UShr8(imm, 4_u8), 1_u8);
  auto bit1 = UAnd8(UShr8(imm, 5_u8), 1_u8);
  auto product0 = FMul(FExtractV64(src1_vec, 0), FExtractV64(src2_vec, 0));
  auto product1 = FMul(FExtractV64(src1_vec, 1), FExtractV64(src2_vec, 1));
  auto dot = FAdd(Select<float64_t>(bit0 != 0_u8, product0, 0.0),
                  Select<float64_t>(bit1 != 0_u8, product1, 0.0));

  auto dst_vec = FClearV64(FReadV64(dst));
  _Pragma("unroll") for (std::size_t i = 0; i < 2; ++i) {
    auto bit = UAnd8(UShr8(imm, TruncTo<uint8_t>(i)), 1_u8);
    dst_vec = FInsertV64(dst_vec, i,
                         Select<float64_t>(bit != 0_u8, dot, 0.0));
  }

  FWriteV64(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(DPPS_XMMdq_XMMdq_IMMb) = DPPS<V128W, V128, V128>;
DEF_ISEL(DPPS_XMMdq_MEMdq_IMMb) = DPPS<V128W, V128, MV128>;

DEF_ISEL(DPPD_XMMdq_XMMdq_IMMb) = DPPD<V128W, V128, V128>;
DEF_ISEL(DPPD_XMMdq_MEMdq_IMMb) = DPPD<V128W, V128, MV128>;

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
  auto tmp_vec_count = vec_count;
  if (vec_count == 8) {
    // For VEX.256, it is basically two 128bits concatenated.
    // The upper half of lhs_vec will be inserted into dst_vec after the lower half of rhs_vec
    tmp_vec_count /= 2;
  }
  _Pragma("unroll") for (size_t index = 0; index < vec_count; index += 2) {
    auto v1 = FExtractV32(lhs_vec, index);
    auto v2 = FExtractV32(lhs_vec, index + 1);
    auto off = Select(index < tmp_vec_count, 0, 2);
    auto i = UAdd(UDiv(UInt32(index), UInt32(2)), UInt32(off));
    dst_vec = FInsertV32(dst_vec, i, FAdd(v1, v2));
  }
  _Pragma("unroll") for (size_t index = 0; index < NumVectorElems(rhs_vec);
                         index += 2) {
    auto v1 = FExtractV32(rhs_vec, index);
    auto v2 = FExtractV32(rhs_vec, index + 1);
    auto off = Select(index < tmp_vec_count, tmp_vec_count, vec_count);
    auto i = UDiv(UAdd(UInt32(index), UInt32(off)), UInt32(2));
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

  static_assert(
      NumVectorElems(lhs_vec) == NumVectorElems(rhs_vec),
      "First and second source vector must have the same number of elements");

  auto vec_count = NumVectorElems(lhs_vec);
  auto tmp_vec_count = vec_count;
  if (vec_count == 4) {
    // For VEX.256, it is basically two 128bits concatenated.
    // The upper half of lhs_vec will be inserted into dst_vec after the lower half of rhs_vec
    tmp_vec_count /= 2;
  }
  // Compute the horizontal packing
  _Pragma("unroll") for (size_t index = 0; index < vec_count; index += 2) {
    auto v1 = FExtractV64(lhs_vec, index);
    auto v2 = FExtractV64(lhs_vec, index + 1);
    auto off = Select(index < tmp_vec_count, 0, 1);
    auto i = UAdd(UDiv(UInt32(index), UInt32(2)), UInt32(off));
    dst_vec = FInsertV64(dst_vec, i, FAdd(v1, v2));
  }
  _Pragma("unroll") for (size_t index = 0; index < vec_count; index += 2) {
    auto v1 = FExtractV64(rhs_vec, index);
    auto v2 = FExtractV64(rhs_vec, index + 1);
    auto off = Select(index < tmp_vec_count, tmp_vec_count, vec_count);
    auto i = UDiv(UAdd(UInt32(index), UInt32(off)), UInt32(2));
    dst_vec = FInsertV64(dst_vec, i, FAdd(v1, v2));
  }
  FWriteV64(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(HSUBPS, D dst, S1 src1, S2 src2) {
  auto lhs_vec = FReadV32(src1);
  auto rhs_vec = FReadV32(src2);
  auto dst_vec = FClearV32(FReadV32(dst));

  // Compute the horizontal packing
  auto vec_count = NumVectorElems(lhs_vec);
  auto tmp_vec_count = vec_count;
  if (vec_count == 8) {
    // For VEX.256, it is basically two 128bits concatenated.
    // The upper half of lhs_vec will be inserted into dst_vec after the lower half of rhs_vec
    tmp_vec_count /= 2;
  }
  _Pragma("unroll") for (size_t index = 0; index < vec_count; index += 2) {
    auto v1 = FExtractV32(lhs_vec, index);
    auto v2 = FExtractV32(lhs_vec, index + 1);
    auto off = Select(index < tmp_vec_count, 0, 2);
    auto i = UAdd(UDiv(UInt32(index), UInt32(2)), UInt32(off));
    dst_vec = FInsertV32(dst_vec, i, FSub(v1, v2));
  }
  _Pragma("unroll") for (size_t index = 0; index < NumVectorElems(rhs_vec);
                         index += 2) {
    auto v1 = FExtractV32(rhs_vec, index);
    auto v2 = FExtractV32(rhs_vec, index + 1);
    auto off = Select(index < tmp_vec_count, tmp_vec_count, vec_count);
    auto i = UDiv(UAdd(UInt32(index), UInt32(off)), UInt32(2));
    dst_vec = FInsertV32(dst_vec, i, FSub(v1, v2));
  }
  FWriteV32(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(HSUBPD, D dst, S1 src1, S2 src2) {
  auto lhs_vec = FReadV64(src1);
  auto rhs_vec = FReadV64(src2);
  auto dst_vec = FClearV64(FReadV64(dst));

  static_assert(
      NumVectorElems(lhs_vec) == NumVectorElems(rhs_vec),
      "First and second source vector must have the same number of elements");

  auto vec_count = NumVectorElems(lhs_vec);
  auto tmp_vec_count = vec_count;
  if (vec_count == 4) {
    // For VEX.256, it is basically two 128bits concatenated.
    // The upper half of lhs_vec will be inserted into dst_vec after the lower half of rhs_vec
    tmp_vec_count /= 2;
  }
  // Compute the horizontal packing
  _Pragma("unroll") for (size_t index = 0; index < vec_count; index += 2) {
    auto v1 = FExtractV64(lhs_vec, index);
    auto v2 = FExtractV64(lhs_vec, index + 1);
    auto off = Select(index < tmp_vec_count, 0, 1);
    auto i = UAdd(UDiv(UInt32(index), UInt32(2)), UInt32(off));
    dst_vec = FInsertV64(dst_vec, i, FSub(v1, v2));
  }
  _Pragma("unroll") for (size_t index = 0; index < vec_count; index += 2) {
    auto v1 = FExtractV64(rhs_vec, index);
    auto v2 = FExtractV64(rhs_vec, index + 1);
    auto off = Select(index < tmp_vec_count, tmp_vec_count, vec_count);
    auto i = UDiv(UAdd(UInt32(index), UInt32(off)), UInt32(2));
    dst_vec = FInsertV64(dst_vec, i, FSub(v1, v2));
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

DEF_ISEL(HSUBPS_XMMps_XMMps) = HSUBPS<V128W, V128, V128>;
DEF_ISEL(HSUBPS_XMMps_MEMps) = HSUBPS<V128W, V128, MV128>;
IF_AVX(DEF_ISEL(VHSUBPS_XMMdq_XMMdq_XMMdq) = HSUBPS<VV128W, V128, V128>;)
IF_AVX(DEF_ISEL(VHSUBPS_XMMdq_XMMdq_MEMdq) = HSUBPS<VV128W, V128, MV128>;)
IF_AVX(DEF_ISEL(VHSUBPS_YMMqq_YMMqq_YMMqq) = HSUBPS<VV256W, V256, V256>;)
IF_AVX(DEF_ISEL(VHSUBPS_YMMqq_YMMqq_MEMqq) = HSUBPS<VV256W, V256, MV256>;)

DEF_ISEL(HSUBPD_XMMpd_XMMpd) = HSUBPD<V128W, V128, V128>;
DEF_ISEL(HSUBPD_XMMpd_MEMpd) = HSUBPD<V128W, V128, MV128>;
IF_AVX(DEF_ISEL(VHSUBPD_XMMdq_XMMdq_XMMdq) = HSUBPD<VV128W, V128, V128>;)
IF_AVX(DEF_ISEL(VHSUBPD_XMMdq_XMMdq_MEMdq) = HSUBPD<VV128W, V128, MV128>;)
IF_AVX(DEF_ISEL(VHSUBPD_YMMqq_YMMqq_YMMqq) = HSUBPD<VV256W, V256, V256>;)
IF_AVX(DEF_ISEL(VHSUBPD_YMMqq_YMMqq_MEMqq) = HSUBPD<VV256W, V256, MV256>;)

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

  FPURoundingControl rounding_mode;
  if (!csr.rp && !csr.rn) {
    rounding_mode = kFPURoundToNearestEven;
  } else if (!csr.rp && csr.rn) {
    rounding_mode = kFPURoundDownNegInf;
  } else if (csr.rp && !csr.rn) {
    rounding_mode = kFPURoundUpInf;
  } else {
    rounding_mode = kFPURoundToZero;
  }
  __remill_fpu_set_rounding(rounding_mode);

  // TODO: MXCSR precision flag (csr.pe) controls exceptions and is not handled here

  return memory;
}

DEF_SEM(STMXCSR, M32W dst) {
  auto &csr = state.x87.fxsave.mxcsr;

  // Store the current FPU rounding mode:
  switch (__remill_fpu_get_rounding()) {
    default:
    case kFPURoundToNearestEven:
      csr.rp = 0;
      csr.rn = 0;
      break;
    case kFPURoundDownNegInf:
      csr.rp = 0;
      csr.rn = 1;
      break;
    case kFPURoundUpInf:
      csr.rp = 1;
      csr.rn = 0;
      break;
    case kFPURoundToZero:
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

namespace {

#define MAKE_PMOVSXx(prefix, suffix, sWidth, dWidth, elementNum) \
  template <typename D, typename S> \
  DEF_SEM(prefix##PMOVSX##suffix, D dst, S src) { \
    auto src_vec = SReadV##sWidth(src); \
    auto dst_vec = SClearV##dWidth(SReadV##dWidth(dst)); \
    _Pragma("unroll") for (auto i = 0u; i < elementNum; i++) { \
      auto v = SExtTo<int##dWidth##_t, int##sWidth##_t>( \
          SExtractV##sWidth(src_vec, i)); \
      dst_vec = SInsertV##dWidth(dst_vec, i, v); \
    } \
    SWriteV##dWidth(dst, dst_vec); \
    return memory; \
  }

MAKE_PMOVSXx(, BW, 8, 16, 8);
MAKE_PMOVSXx(, BD, 8, 32, 4);
MAKE_PMOVSXx(, BQ, 8, 64, 2);
MAKE_PMOVSXx(, WD, 16, 32, 4);
MAKE_PMOVSXx(, WQ, 16, 64, 2);
MAKE_PMOVSXx(, DQ, 32, 64, 2);
#if HAS_FEATURE_AVX
MAKE_PMOVSXx(V, BW, 8, 16, 16);
MAKE_PMOVSXx(V, BD, 8, 32, 8);
MAKE_PMOVSXx(V, BQ, 8, 64, 4);
MAKE_PMOVSXx(V, WD, 16, 32, 8);
MAKE_PMOVSXx(V, WQ, 16, 64, 4);
MAKE_PMOVSXx(V, DQ, 32, 64, 4);

#endif  // HAS_FEATURE_AVX

#undef MAKE_PMOVSXx

}  // namespace

DEF_ISEL(PMOVSXBW_XMMdq_MEMq) = PMOVSXBW<V128W, MV64>;
DEF_ISEL(PMOVSXBW_XMMdq_XMMq) = PMOVSXBW<V128W, V128>;
IF_AVX(DEF_ISEL(VPMOVSXBW_XMMdq_XMMq) = PMOVSXBW<VV128W, V128>;)
IF_AVX(DEF_ISEL(VPMOVSXBW_XMMdq_MEMq) = PMOVSXBW<VV128W, MV64>;)
IF_AVX(DEF_ISEL(VPMOVSXBW_YMMqq_XMMdq) = VPMOVSXBW<VV256W, V256>;)
IF_AVX(DEF_ISEL(VPMOVSXBW_YMMqq_MEMdq) = VPMOVSXBW<VV256W, MV128>;)

DEF_ISEL(PMOVSXBD_XMMdq_MEMd) = PMOVSXBD<V128W, MV32>;
DEF_ISEL(PMOVSXBD_XMMdq_XMMd) = PMOVSXBD<V128W, V128>;
IF_AVX(DEF_ISEL(VPMOVSXBD_XMMdq_XMMd) = PMOVSXBD<VV128W, V128>;)
IF_AVX(DEF_ISEL(VPMOVSXBD_XMMdq_MEMd) = PMOVSXBD<VV128W, MV32>;)
IF_AVX(DEF_ISEL(VPMOVSXBD_YMMqq_XMMq) = VPMOVSXBD<VV256W, V256>;)
IF_AVX(DEF_ISEL(VPMOVSXBD_YMMqq_MEMq) = VPMOVSXBD<VV256W, MV64>;)

DEF_ISEL(PMOVSXBQ_XMMdq_MEMw) = PMOVSXBQ<V128W, MV16>;
DEF_ISEL(PMOVSXBQ_XMMdq_XMMw) = PMOVSXBQ<V128W, V128>;
IF_AVX(DEF_ISEL(VPMOVSXBQ_XMMdq_XMMw) = PMOVSXBQ<VV128W, V128>;)
IF_AVX(DEF_ISEL(VPMOVSXBQ_XMMdq_MEMw) = PMOVSXBQ<VV128W, MV16>;)
IF_AVX(DEF_ISEL(VPMOVSXBQ_YMMqq_XMMd) = VPMOVSXBQ<VV256W, V256>;)
IF_AVX(DEF_ISEL(VPMOVSXBQ_YMMqq_MEMd) = VPMOVSXBQ<VV256W, MV32>;)

DEF_ISEL(PMOVSXWD_XMMdq_MEMq) = PMOVSXWD<V128W, MV64>;
DEF_ISEL(PMOVSXWD_XMMdq_XMMq) = PMOVSXWD<V128W, V128>;
IF_AVX(DEF_ISEL(VPMOVSXWD_XMMdq_XMMq) = PMOVSXWD<VV128W, V128>;)
IF_AVX(DEF_ISEL(VPMOVSXWD_XMMdq_MEMq) = PMOVSXWD<VV128W, MV64>;)
IF_AVX(DEF_ISEL(VPMOVSXWD_YMMqq_XMMdq) = VPMOVSXWD<VV256W, V256>;)
IF_AVX(DEF_ISEL(VPMOVSXWD_YMMqq_MEMdq) = VPMOVSXWD<VV256W, MV128>;)

DEF_ISEL(PMOVSXWQ_XMMdq_MEMd) = PMOVSXWQ<V128W, MV32>;
DEF_ISEL(PMOVSXWQ_XMMdq_XMMd) = PMOVSXWQ<V128W, V128>;
IF_AVX(DEF_ISEL(VPMOVSXWQ_XMMdq_XMMd) = PMOVSXWQ<VV128W, V128>;)
IF_AVX(DEF_ISEL(VPMOVSXWQ_XMMdq_MEMd) = PMOVSXWQ<VV128W, MV32>;)
IF_AVX(DEF_ISEL(VPMOVSXWQ_YMMqq_XMMq) = VPMOVSXWQ<VV256W, V256>;)
IF_AVX(DEF_ISEL(VPMOVSXWQ_YMMqq_MEMq) = VPMOVSXWQ<VV256W, MV64>;)

DEF_ISEL(PMOVSXDQ_XMMdq_MEMq) = PMOVSXDQ<V128W, MV64>;
DEF_ISEL(PMOVSXDQ_XMMdq_XMMq) = PMOVSXDQ<V128W, V128>;
IF_AVX(DEF_ISEL(VPMOVSXDQ_XMMdq_XMMq) = PMOVSXDQ<VV128W, V128>;)
IF_AVX(DEF_ISEL(VPMOVSXDQ_XMMdq_MEMq) = PMOVSXDQ<VV128W, MV64>;)
IF_AVX(DEF_ISEL(VPMOVSXDQ_YMMqq_XMMdq) = VPMOVSXDQ<VV256W, V256>;)
IF_AVX(DEF_ISEL(VPMOVSXDQ_YMMqq_MEMdq) = VPMOVSXDQ<VV256W, MV128>;)

namespace {

#define MAKE_PMOVZXx(prefix, suffix, sWidth, dWidth, elementNum) \
  template <typename D, typename S> \
  DEF_SEM(prefix##PMOVZX##suffix, D dst, S src) { \
    auto src_vec = SReadV##sWidth(src); \
    auto dst_vec = UClearV##dWidth(UReadV##dWidth(dst)); \
    _Pragma("unroll") for (auto i = 0u; i < elementNum; i++) { \
      auto v = ZExtTo<int##dWidth##_t, int##sWidth##_t>( \
          SExtractV##sWidth(src_vec, i)); \
      dst_vec = UInsertV##dWidth(dst_vec, i, v); \
    } \
    UWriteV##dWidth(dst, dst_vec); \
    return memory; \
  }

MAKE_PMOVZXx(, BW, 8, 16, 8);
MAKE_PMOVZXx(, BD, 8, 32, 4);
MAKE_PMOVZXx(, BQ, 8, 64, 2);
MAKE_PMOVZXx(, WD, 16, 32, 4);
MAKE_PMOVZXx(, WQ, 16, 64, 2);
MAKE_PMOVZXx(, DQ, 32, 64, 2);
#if HAS_FEATURE_AVX
MAKE_PMOVZXx(V, BW, 8, 16, 16);
MAKE_PMOVZXx(V, BD, 8, 32, 8);
MAKE_PMOVZXx(V, BQ, 8, 64, 4);
MAKE_PMOVZXx(V, WD, 16, 32, 8);
MAKE_PMOVZXx(V, WQ, 16, 64, 4);
MAKE_PMOVZXx(V, DQ, 32, 64, 4);

#endif  // HAS_FEATURE_AVX

#undef MAKE_PMOVSXx

}  // namespace

DEF_ISEL(PMOVZXBW_XMMdq_MEMq) = PMOVZXBW<V128W, MV64>;
DEF_ISEL(PMOVZXBW_XMMdq_XMMq) = PMOVZXBW<V128W, V128>;
IF_AVX(DEF_ISEL(VPMOVZXBW_XMMdq_XMMq) = PMOVZXBW<VV128W, V128>;)
IF_AVX(DEF_ISEL(VPMOVZXBW_XMMdq_MEMq) = PMOVZXBW<VV128W, MV64>;)
IF_AVX(DEF_ISEL(VPMOVZXBW_YMMqq_XMMdq) = VPMOVZXBW<VV256W, V256>;)
IF_AVX(DEF_ISEL(VPMOVZXBW_YMMqq_MEMdq) = VPMOVZXBW<VV256W, MV128>;)

DEF_ISEL(PMOVZXBD_XMMdq_MEMd) = PMOVZXBD<V128W, MV32>;
DEF_ISEL(PMOVZXBD_XMMdq_XMMd) = PMOVZXBD<V128W, V128>;
IF_AVX(DEF_ISEL(VPMOVZXBD_XMMdq_XMMd) = PMOVZXBD<VV128W, V128>;)
IF_AVX(DEF_ISEL(VPMOVZXBD_XMMdq_MEMd) = PMOVZXBD<VV128W, MV32>;)
IF_AVX(DEF_ISEL(VPMOVZXBD_YMMqq_XMMq) = VPMOVZXBD<VV256W, V256>;)
IF_AVX(DEF_ISEL(VPMOVZXBD_YMMqq_MEMq) = VPMOVZXBD<VV256W, MV64>;)

DEF_ISEL(PMOVZXBQ_XMMdq_MEMw) = PMOVZXBQ<V128W, MV16>;
DEF_ISEL(PMOVZXBQ_XMMdq_XMMw) = PMOVZXBQ<V128W, V128>;
IF_AVX(DEF_ISEL(VPMOVZXBQ_XMMdq_XMMw) = PMOVZXBQ<VV128W, V128>;)
IF_AVX(DEF_ISEL(VPMOVZXBQ_XMMdq_MEMw) = PMOVZXBQ<VV128W, MV16>;)
IF_AVX(DEF_ISEL(VPMOVZXBQ_YMMqq_XMMd) = VPMOVZXBQ<VV256W, V256>;)
IF_AVX(DEF_ISEL(VPMOVZXBQ_YMMqq_MEMd) = VPMOVZXBQ<VV256W, MV32>;)

DEF_ISEL(PMOVZXWD_XMMdq_MEMq) = PMOVZXWD<V128W, MV64>;
DEF_ISEL(PMOVZXWD_XMMdq_XMMq) = PMOVZXWD<V128W, V128>;
IF_AVX(DEF_ISEL(VPMOVZXWD_XMMdq_XMMq) = PMOVZXWD<VV128W, V128>;)
IF_AVX(DEF_ISEL(VPMOVZXWD_XMMdq_MEMq) = PMOVZXWD<VV128W, MV64>;)
IF_AVX(DEF_ISEL(VPMOVZXWD_YMMqq_XMMdq) = VPMOVZXWD<VV256W, V256>;)
IF_AVX(DEF_ISEL(VPMOVZXWD_YMMqq_MEMdq) = VPMOVZXWD<VV256W, MV128>;)

DEF_ISEL(PMOVZXWQ_XMMdq_MEMd) = PMOVZXWQ<V128W, MV32>;
DEF_ISEL(PMOVZXWQ_XMMdq_XMMd) = PMOVZXWQ<V128W, V128>;
IF_AVX(DEF_ISEL(VPMOVZXWQ_XMMdq_XMMd) = PMOVZXWQ<VV128W, V128>;)
IF_AVX(DEF_ISEL(VPMOVZXWQ_XMMdq_MEMd) = PMOVZXWQ<VV128W, MV32>;)
IF_AVX(DEF_ISEL(VPMOVZXWQ_YMMqq_XMMq) = VPMOVZXWQ<VV256W, V256>;)
IF_AVX(DEF_ISEL(VPMOVZXWQ_YMMqq_MEMq) = VPMOVZXWQ<VV256W, MV64>;)

DEF_ISEL(PMOVZXDQ_XMMdq_MEMq) = PMOVZXDQ<V128W, MV64>;
DEF_ISEL(PMOVZXDQ_XMMdq_XMMq) = PMOVZXDQ<V128W, V128>;
IF_AVX(DEF_ISEL(VPMOVZXDQ_XMMdq_XMMq) = PMOVZXDQ<VV128W, V128>;)
IF_AVX(DEF_ISEL(VPMOVZXDQ_XMMdq_MEMq) = PMOVZXDQ<VV128W, MV64>;)
IF_AVX(DEF_ISEL(VPMOVZXDQ_YMMqq_XMMdq) = VPMOVZXDQ<VV256W, V256>;)
IF_AVX(DEF_ISEL(VPMOVZXDQ_YMMqq_MEMdq) = VPMOVZXDQ<VV256W, MV128>;)

namespace {

#define MAKE_ADDSUBx(suffix, element_width) \
  template <typename D, typename S1, typename S2> \
  DEF_SEM(ADDSUB##suffix, D dst, S1 src1, S2 src2) { \
    auto src1_vec = FReadV##element_width(src1); \
    auto src2_vec = FReadV##element_width(src2); \
    auto dst_vec = FClearV##element_width(FReadV##element_width(dst)); \
\
    auto num_elements = NumVectorElems(src1_vec); \
\
    _Pragma("unroll") for (auto idx = 0u; idx < num_elements; ++idx) { \
      auto src1_val = FExtractV##element_width(src1_vec, idx); \
      auto src2_val = FExtractV##element_width(src2_vec, idx); \
      auto op_val = \
          Select(idx % 2, FAdd(src1_val, src2_val), FSub(src1_val, src2_val)); \
      dst_vec = FInsertV##element_width(dst_vec, idx, op_val); \
    } \
    FWriteV##element_width(dst, dst_vec); \
    return memory; \
  }

MAKE_ADDSUBx(PS, 32) MAKE_ADDSUBx(PD, 64)

#undef MAKE_ADDSUBx
}  // namespace

DEF_ISEL(ADDSUBPS_XMMps_MEMps) = ADDSUBPS<V128W, V128, MV128>;
DEF_ISEL(ADDSUBPS_XMMps_XMMps) = ADDSUBPS<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VADDSUBPS_XMMdq_XMMdq_MEMdq) = ADDSUBPS<VV128W, V128, MV128>;)
IF_AVX(DEF_ISEL(VADDSUBPS_XMMdq_XMMdq_XMMdq) = ADDSUBPS<VV128W, V128, V128>;)
IF_AVX(DEF_ISEL(VADDSUBPS_YMMqq_YMMqq_MEMqq) = ADDSUBPS<VV256W, V256, MV256>;)
IF_AVX(DEF_ISEL(VADDSUBPS_YMMqq_YMMqq_YMMqq) = ADDSUBPS<VV256W, V256, V128>;)

DEF_ISEL(ADDSUBPD_XMMpd_MEMpd) = ADDSUBPD<V128W, V128, MV128>;
DEF_ISEL(ADDSUBPD_XMMpd_XMMpd) = ADDSUBPD<V128W, V128, V128>;
IF_AVX(DEF_ISEL(VADDSUBPD_XMMdq_XMMdq_MEMdq) = ADDSUBPD<VV128W, V128, MV128>;)
IF_AVX(DEF_ISEL(VADDSUBPD_XMMdq_XMMdq_XMMdq) = ADDSUBPD<VV128W, V128, V128>;)
IF_AVX(DEF_ISEL(VADDSUBPD_YMMqq_YMMqq_MEMqq) = ADDSUBPD<VV256W, V256, MV256>;)
IF_AVX(DEF_ISEL(VADDSUBPD_YMMqq_YMMqq_YMMqq) = ADDSUBPD<VV256W, V256, V128>;)

namespace {

static const uint8_t kAesSBox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

static const uint8_t kAesInvSBox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d};

ALWAYS_INLINE static uint8_t AesSBox(uint8_t value) { return kAesSBox[value]; }
ALWAYS_INLINE static uint8_t AesInvSBox(uint8_t value) { return kAesInvSBox[value]; }

ALWAYS_INLINE static uint8_t AesXtime(uint8_t value) {
  return UXor(UShl(value, 1_u8),
              Select<uint8_t>(UCmpNeq(UAnd(value, 0x80_u8), 0_u8), 0x1b_u8, 0_u8));
}

ALWAYS_INLINE static uint8_t AesMul(uint8_t value, uint8_t factor) {
  uint8_t result = 0;
  _Pragma("unroll") for (auto i = 0u; i < 8u; ++i) {
    result = Select<uint8_t>(UCmpNeq(UAnd(factor, 1_u8), 0_u8), UXor(result, value), result);
    value = AesXtime(value);
    factor = UShr(factor, 1_u8);
  }
  return result;
}

ALWAYS_INLINE static uint32_t AesPack4(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3) {
  return UOr(UOr(ZExtTo<uint32_t>(b0), UShl(ZExtTo<uint32_t>(b1), 8_u32)),
             UOr(UShl(ZExtTo<uint32_t>(b2), 16_u32), UShl(ZExtTo<uint32_t>(b3), 24_u32)));
}

ALWAYS_INLINE static uint8_t AesPackByte(uint32_t value, uint32_t index) {
  return UInt8(UShr(value, UMul(index, 8_u32)));
}

ALWAYS_INLINE static uint32_t AesMixColumn(uint8_t s0, uint8_t s1, uint8_t s2, uint8_t s3) {
  auto r0 = UXor(UXor(AesMul(s0, 2_u8), AesMul(s1, 3_u8)), UXor(s2, s3));
  auto r1 = UXor(UXor(s0, AesMul(s1, 2_u8)), UXor(AesMul(s2, 3_u8), s3));
  auto r2 = UXor(UXor(s0, s1), UXor(AesMul(s2, 2_u8), AesMul(s3, 3_u8)));
  auto r3 = UXor(UXor(AesMul(s0, 3_u8), s1), UXor(s2, AesMul(s3, 2_u8)));
  return AesPack4(r0, r1, r2, r3);
}

ALWAYS_INLINE static uint32_t AesInvMixColumn(uint8_t s0, uint8_t s1, uint8_t s2, uint8_t s3) {
  auto r0 = UXor(UXor(AesMul(s0, 0x0e_u8), AesMul(s1, 0x0b_u8)),
                 UXor(AesMul(s2, 0x0d_u8), AesMul(s3, 0x09_u8)));
  auto r1 = UXor(UXor(AesMul(s0, 0x09_u8), AesMul(s1, 0x0e_u8)),
                 UXor(AesMul(s2, 0x0b_u8), AesMul(s3, 0x0d_u8)));
  auto r2 = UXor(UXor(AesMul(s0, 0x0d_u8), AesMul(s1, 0x09_u8)),
                 UXor(AesMul(s2, 0x0e_u8), AesMul(s3, 0x0b_u8)));
  auto r3 = UXor(UXor(AesMul(s0, 0x0b_u8), AesMul(s1, 0x0d_u8)),
                 UXor(AesMul(s2, 0x09_u8), AesMul(s3, 0x0e_u8)));
  return AesPack4(r0, r1, r2, r3);
}

#define AES_XOR_INSERT(vec, key, idx, value) \
  vec = UInsertV8(vec, idx, UXor(value, UExtractV8(key, idx)))
#define AES_MIX_INSERT(vec, key, col, idx) \
  AES_XOR_INSERT(vec, key, idx, AesPackByte(col, (idx % 4)))

template <typename D, typename S1, typename S2>
DEF_SEM(AESENC, D dst, S1 src1, S2 src2) {
  auto state_vec = UReadV8(src1);
  auto key_vec = UReadV8(src2);
  auto dst_vec = UClearV8(UReadV8(dst));
  auto c0 = AesMixColumn(AesSBox(UExtractV8(state_vec, 0)), AesSBox(UExtractV8(state_vec, 5)), AesSBox(UExtractV8(state_vec, 10)), AesSBox(UExtractV8(state_vec, 15)));
  auto c1 = AesMixColumn(AesSBox(UExtractV8(state_vec, 4)), AesSBox(UExtractV8(state_vec, 9)), AesSBox(UExtractV8(state_vec, 14)), AesSBox(UExtractV8(state_vec, 3)));
  auto c2 = AesMixColumn(AesSBox(UExtractV8(state_vec, 8)), AesSBox(UExtractV8(state_vec, 13)), AesSBox(UExtractV8(state_vec, 2)), AesSBox(UExtractV8(state_vec, 7)));
  auto c3 = AesMixColumn(AesSBox(UExtractV8(state_vec, 12)), AesSBox(UExtractV8(state_vec, 1)), AesSBox(UExtractV8(state_vec, 6)), AesSBox(UExtractV8(state_vec, 11)));
  AES_MIX_INSERT(dst_vec, key_vec, c0, 0); AES_MIX_INSERT(dst_vec, key_vec, c0, 1); AES_MIX_INSERT(dst_vec, key_vec, c0, 2); AES_MIX_INSERT(dst_vec, key_vec, c0, 3);
  AES_MIX_INSERT(dst_vec, key_vec, c1, 4); AES_MIX_INSERT(dst_vec, key_vec, c1, 5); AES_MIX_INSERT(dst_vec, key_vec, c1, 6); AES_MIX_INSERT(dst_vec, key_vec, c1, 7);
  AES_MIX_INSERT(dst_vec, key_vec, c2, 8); AES_MIX_INSERT(dst_vec, key_vec, c2, 9); AES_MIX_INSERT(dst_vec, key_vec, c2, 10); AES_MIX_INSERT(dst_vec, key_vec, c2, 11);
  AES_MIX_INSERT(dst_vec, key_vec, c3, 12); AES_MIX_INSERT(dst_vec, key_vec, c3, 13); AES_MIX_INSERT(dst_vec, key_vec, c3, 14); AES_MIX_INSERT(dst_vec, key_vec, c3, 15);
  UWriteV8(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(AESENCLAST, D dst, S1 src1, S2 src2) {
  auto state_vec = UReadV8(src1);
  auto key_vec = UReadV8(src2);
  auto dst_vec = UClearV8(UReadV8(dst));
  AES_XOR_INSERT(dst_vec, key_vec, 0, AesSBox(UExtractV8(state_vec, 0)));
  AES_XOR_INSERT(dst_vec, key_vec, 1, AesSBox(UExtractV8(state_vec, 5)));
  AES_XOR_INSERT(dst_vec, key_vec, 2, AesSBox(UExtractV8(state_vec, 10)));
  AES_XOR_INSERT(dst_vec, key_vec, 3, AesSBox(UExtractV8(state_vec, 15)));
  AES_XOR_INSERT(dst_vec, key_vec, 4, AesSBox(UExtractV8(state_vec, 4)));
  AES_XOR_INSERT(dst_vec, key_vec, 5, AesSBox(UExtractV8(state_vec, 9)));
  AES_XOR_INSERT(dst_vec, key_vec, 6, AesSBox(UExtractV8(state_vec, 14)));
  AES_XOR_INSERT(dst_vec, key_vec, 7, AesSBox(UExtractV8(state_vec, 3)));
  AES_XOR_INSERT(dst_vec, key_vec, 8, AesSBox(UExtractV8(state_vec, 8)));
  AES_XOR_INSERT(dst_vec, key_vec, 9, AesSBox(UExtractV8(state_vec, 13)));
  AES_XOR_INSERT(dst_vec, key_vec, 10, AesSBox(UExtractV8(state_vec, 2)));
  AES_XOR_INSERT(dst_vec, key_vec, 11, AesSBox(UExtractV8(state_vec, 7)));
  AES_XOR_INSERT(dst_vec, key_vec, 12, AesSBox(UExtractV8(state_vec, 12)));
  AES_XOR_INSERT(dst_vec, key_vec, 13, AesSBox(UExtractV8(state_vec, 1)));
  AES_XOR_INSERT(dst_vec, key_vec, 14, AesSBox(UExtractV8(state_vec, 6)));
  AES_XOR_INSERT(dst_vec, key_vec, 15, AesSBox(UExtractV8(state_vec, 11)));
  UWriteV8(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(AESDEC, D dst, S1 src1, S2 src2) {
  auto state_vec = UReadV8(src1);
  auto key_vec = UReadV8(src2);
  auto dst_vec = UClearV8(UReadV8(dst));
  auto c0 = AesInvMixColumn(AesInvSBox(UExtractV8(state_vec, 0)), AesInvSBox(UExtractV8(state_vec, 13)), AesInvSBox(UExtractV8(state_vec, 10)), AesInvSBox(UExtractV8(state_vec, 7)));
  auto c1 = AesInvMixColumn(AesInvSBox(UExtractV8(state_vec, 4)), AesInvSBox(UExtractV8(state_vec, 1)), AesInvSBox(UExtractV8(state_vec, 14)), AesInvSBox(UExtractV8(state_vec, 11)));
  auto c2 = AesInvMixColumn(AesInvSBox(UExtractV8(state_vec, 8)), AesInvSBox(UExtractV8(state_vec, 5)), AesInvSBox(UExtractV8(state_vec, 2)), AesInvSBox(UExtractV8(state_vec, 15)));
  auto c3 = AesInvMixColumn(AesInvSBox(UExtractV8(state_vec, 12)), AesInvSBox(UExtractV8(state_vec, 9)), AesInvSBox(UExtractV8(state_vec, 6)), AesInvSBox(UExtractV8(state_vec, 3)));
  AES_MIX_INSERT(dst_vec, key_vec, c0, 0); AES_MIX_INSERT(dst_vec, key_vec, c0, 1); AES_MIX_INSERT(dst_vec, key_vec, c0, 2); AES_MIX_INSERT(dst_vec, key_vec, c0, 3);
  AES_MIX_INSERT(dst_vec, key_vec, c1, 4); AES_MIX_INSERT(dst_vec, key_vec, c1, 5); AES_MIX_INSERT(dst_vec, key_vec, c1, 6); AES_MIX_INSERT(dst_vec, key_vec, c1, 7);
  AES_MIX_INSERT(dst_vec, key_vec, c2, 8); AES_MIX_INSERT(dst_vec, key_vec, c2, 9); AES_MIX_INSERT(dst_vec, key_vec, c2, 10); AES_MIX_INSERT(dst_vec, key_vec, c2, 11);
  AES_MIX_INSERT(dst_vec, key_vec, c3, 12); AES_MIX_INSERT(dst_vec, key_vec, c3, 13); AES_MIX_INSERT(dst_vec, key_vec, c3, 14); AES_MIX_INSERT(dst_vec, key_vec, c3, 15);
  UWriteV8(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(AESDECLAST, D dst, S1 src1, S2 src2) {
  auto state_vec = UReadV8(src1);
  auto key_vec = UReadV8(src2);
  auto dst_vec = UClearV8(UReadV8(dst));
  AES_XOR_INSERT(dst_vec, key_vec, 0, AesInvSBox(UExtractV8(state_vec, 0)));
  AES_XOR_INSERT(dst_vec, key_vec, 1, AesInvSBox(UExtractV8(state_vec, 13)));
  AES_XOR_INSERT(dst_vec, key_vec, 2, AesInvSBox(UExtractV8(state_vec, 10)));
  AES_XOR_INSERT(dst_vec, key_vec, 3, AesInvSBox(UExtractV8(state_vec, 7)));
  AES_XOR_INSERT(dst_vec, key_vec, 4, AesInvSBox(UExtractV8(state_vec, 4)));
  AES_XOR_INSERT(dst_vec, key_vec, 5, AesInvSBox(UExtractV8(state_vec, 1)));
  AES_XOR_INSERT(dst_vec, key_vec, 6, AesInvSBox(UExtractV8(state_vec, 14)));
  AES_XOR_INSERT(dst_vec, key_vec, 7, AesInvSBox(UExtractV8(state_vec, 11)));
  AES_XOR_INSERT(dst_vec, key_vec, 8, AesInvSBox(UExtractV8(state_vec, 8)));
  AES_XOR_INSERT(dst_vec, key_vec, 9, AesInvSBox(UExtractV8(state_vec, 5)));
  AES_XOR_INSERT(dst_vec, key_vec, 10, AesInvSBox(UExtractV8(state_vec, 2)));
  AES_XOR_INSERT(dst_vec, key_vec, 11, AesInvSBox(UExtractV8(state_vec, 15)));
  AES_XOR_INSERT(dst_vec, key_vec, 12, AesInvSBox(UExtractV8(state_vec, 12)));
  AES_XOR_INSERT(dst_vec, key_vec, 13, AesInvSBox(UExtractV8(state_vec, 9)));
  AES_XOR_INSERT(dst_vec, key_vec, 14, AesInvSBox(UExtractV8(state_vec, 6)));
  AES_XOR_INSERT(dst_vec, key_vec, 15, AesInvSBox(UExtractV8(state_vec, 3)));
  UWriteV8(dst, dst_vec);
  return memory;
}

template <typename D, typename S>
DEF_SEM(AESIMC, D dst, S src) {
  auto src_vec = UReadV8(src);
  auto dst_vec = UClearV8(UReadV8(dst));
  auto c0 = AesInvMixColumn(UExtractV8(src_vec, 0), UExtractV8(src_vec, 1), UExtractV8(src_vec, 2), UExtractV8(src_vec, 3));
  auto c1 = AesInvMixColumn(UExtractV8(src_vec, 4), UExtractV8(src_vec, 5), UExtractV8(src_vec, 6), UExtractV8(src_vec, 7));
  auto c2 = AesInvMixColumn(UExtractV8(src_vec, 8), UExtractV8(src_vec, 9), UExtractV8(src_vec, 10), UExtractV8(src_vec, 11));
  auto c3 = AesInvMixColumn(UExtractV8(src_vec, 12), UExtractV8(src_vec, 13), UExtractV8(src_vec, 14), UExtractV8(src_vec, 15));
  dst_vec = UInsertV8(dst_vec, 0, AesPackByte(c0, 0_u32)); dst_vec = UInsertV8(dst_vec, 1, AesPackByte(c0, 1_u32)); dst_vec = UInsertV8(dst_vec, 2, AesPackByte(c0, 2_u32)); dst_vec = UInsertV8(dst_vec, 3, AesPackByte(c0, 3_u32));
  dst_vec = UInsertV8(dst_vec, 4, AesPackByte(c1, 0_u32)); dst_vec = UInsertV8(dst_vec, 5, AesPackByte(c1, 1_u32)); dst_vec = UInsertV8(dst_vec, 6, AesPackByte(c1, 2_u32)); dst_vec = UInsertV8(dst_vec, 7, AesPackByte(c1, 3_u32));
  dst_vec = UInsertV8(dst_vec, 8, AesPackByte(c2, 0_u32)); dst_vec = UInsertV8(dst_vec, 9, AesPackByte(c2, 1_u32)); dst_vec = UInsertV8(dst_vec, 10, AesPackByte(c2, 2_u32)); dst_vec = UInsertV8(dst_vec, 11, AesPackByte(c2, 3_u32));
  dst_vec = UInsertV8(dst_vec, 12, AesPackByte(c3, 0_u32)); dst_vec = UInsertV8(dst_vec, 13, AesPackByte(c3, 1_u32)); dst_vec = UInsertV8(dst_vec, 14, AesPackByte(c3, 2_u32)); dst_vec = UInsertV8(dst_vec, 15, AesPackByte(c3, 3_u32));
  UWriteV8(dst, dst_vec);
  return memory;
}

template <typename D, typename S>
DEF_SEM(AESKEYGENASSIST, D dst, S src, I64 imm) {
  auto src_vec = UReadV8(src);
  auto dst_vec = UClearV8(UReadV8(dst));
  auto rcon = UInt8(Read(imm));
  auto b4 = AesSBox(UExtractV8(src_vec, 4)); auto b5 = AesSBox(UExtractV8(src_vec, 5)); auto b6 = AesSBox(UExtractV8(src_vec, 6)); auto b7 = AesSBox(UExtractV8(src_vec, 7));
  auto b12 = AesSBox(UExtractV8(src_vec, 12)); auto b13 = AesSBox(UExtractV8(src_vec, 13)); auto b14 = AesSBox(UExtractV8(src_vec, 14)); auto b15 = AesSBox(UExtractV8(src_vec, 15));
  dst_vec = UInsertV8(dst_vec, 0, b4); dst_vec = UInsertV8(dst_vec, 1, b5); dst_vec = UInsertV8(dst_vec, 2, b6); dst_vec = UInsertV8(dst_vec, 3, b7);
  dst_vec = UInsertV8(dst_vec, 4, UXor(b5, rcon)); dst_vec = UInsertV8(dst_vec, 5, b6); dst_vec = UInsertV8(dst_vec, 6, b7); dst_vec = UInsertV8(dst_vec, 7, b4);
  dst_vec = UInsertV8(dst_vec, 8, b12); dst_vec = UInsertV8(dst_vec, 9, b13); dst_vec = UInsertV8(dst_vec, 10, b14); dst_vec = UInsertV8(dst_vec, 11, b15);
  dst_vec = UInsertV8(dst_vec, 12, UXor(b13, rcon)); dst_vec = UInsertV8(dst_vec, 13, b14); dst_vec = UInsertV8(dst_vec, 14, b15); dst_vec = UInsertV8(dst_vec, 15, b12);
  UWriteV8(dst, dst_vec);
  return memory;
}

#undef AES_MIX_INSERT
#undef AES_XOR_INSERT

}  // namespace

DEF_ISEL(AESENC_XMMdq_XMMdq) = AESENC<V128W, V128, V128>;
DEF_ISEL(AESENCLAST_XMMdq_XMMdq) = AESENCLAST<V128W, V128, V128>;
DEF_ISEL(AESDEC_XMMdq_XMMdq) = AESDEC<V128W, V128, V128>;
DEF_ISEL(AESDECLAST_XMMdq_XMMdq) = AESDECLAST<V128W, V128, V128>;
DEF_ISEL(AESIMC_XMMdq_XMMdq) = AESIMC<V128W, V128>;
DEF_ISEL(AESKEYGENASSIST_XMMdq_XMMdq_IMMb) = AESKEYGENASSIST<V128W, V128>;

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(SHA1MSG1, D dst, S1 src1, S2 src2) {
  auto src1_vec = UReadV32(src1);
  auto src2_vec = UReadV32(src2);
  auto dst_vec = UClearV32(UReadV32(dst));

  dst_vec = UInsertV32(dst_vec, 0,
                       UXor(UExtractV32(src1_vec, 0),
                            UExtractV32(src2_vec, 2)));
  dst_vec = UInsertV32(dst_vec, 1,
                       UXor(UExtractV32(src1_vec, 1),
                            UExtractV32(src2_vec, 3)));
  dst_vec = UInsertV32(dst_vec, 2,
                       UXor(UExtractV32(src1_vec, 2),
                            UExtractV32(src1_vec, 0)));
  dst_vec = UInsertV32(dst_vec, 3,
                       UXor(UExtractV32(src1_vec, 3),
                            UExtractV32(src1_vec, 1)));

  UWriteV32(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(SHA1MSG1_XMMi32_XMMi32_SHA) = SHA1MSG1<V128W, V128, V128>;
DEF_ISEL(SHA1MSG1_XMMi32_MEMi32_SHA) = SHA1MSG1<V128W, V128, MV128>;

namespace {

ALWAYS_INLINE static uint32_t ShaRol32(uint32_t value, uint32_t shift) {
  return UOr(UShl(value, shift), UShr(value, USub(32_u32, shift)));
}

template <typename D, typename S1, typename S2>
DEF_SEM(SHA1MSG2, D dst, S1 src1, S2 src2) {
  auto src1_vec = UReadV32(src1);
  auto src2_vec = UReadV32(src2);
  auto dst_vec = UClearV32(UReadV32(dst));

  auto word3 = ShaRol32(UXor(UExtractV32(src1_vec, 3),
                             UExtractV32(src2_vec, 2)),
                        1_u32);
  auto word2 = ShaRol32(UXor(UExtractV32(src1_vec, 2),
                             UExtractV32(src2_vec, 1)),
                        1_u32);
  auto word1 = ShaRol32(UXor(UExtractV32(src1_vec, 1),
                             UExtractV32(src2_vec, 0)),
                        1_u32);
  auto word0 = ShaRol32(UXor(UExtractV32(src1_vec, 0), word3), 1_u32);

  dst_vec = UInsertV32(dst_vec, 0, word0);
  dst_vec = UInsertV32(dst_vec, 1, word1);
  dst_vec = UInsertV32(dst_vec, 2, word2);
  dst_vec = UInsertV32(dst_vec, 3, word3);
  UWriteV32(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(SHA1MSG2_XMMi32_XMMi32_SHA) = SHA1MSG2<V128W, V128, V128>;
DEF_ISEL(SHA1MSG2_XMMi32_MEMi32_SHA) = SHA1MSG2<V128W, V128, MV128>;

namespace {

ALWAYS_INLINE static uint32_t ShaRor32(uint32_t value, uint32_t shift) {
  return UOr(UShr(value, shift), UShl(value, USub(32_u32, shift)));
}

template <typename D, typename S1, typename S2>
DEF_SEM(SHA1NEXTE, D dst, S1 src1, S2 src2) {
  auto src1_vec = UReadV32(src1);
  auto src2_vec = UReadV32(src2);
  auto dst_vec = src2_vec;
  auto next_e = UAdd(UExtractV32(src2_vec, 3),
                     ShaRor32(UExtractV32(src1_vec, 3), 2_u32));
  dst_vec = UInsertV32(dst_vec, 3, next_e);
  UWriteV32(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(SHA1NEXTE_XMMi32_XMMi32_SHA) = SHA1NEXTE<V128W, V128, V128>;
DEF_ISEL(SHA1NEXTE_XMMi32_MEMi32_SHA) = SHA1NEXTE<V128W, V128, MV128>;

namespace {

ALWAYS_INLINE static uint32_t Sha1Choose(uint32_t b, uint32_t c, uint32_t d) {
  return UXor(UAnd(b, c), UAnd(UNot(b), d));
}

ALWAYS_INLINE static uint32_t Sha1Parity(uint32_t b, uint32_t c, uint32_t d) {
  return UXor(UXor(b, c), d);
}

ALWAYS_INLINE static uint32_t Sha1Majority(uint32_t b, uint32_t c, uint32_t d) {
  return UXor(UXor(UAnd(b, c), UAnd(b, d)), UAnd(c, d));
}

ALWAYS_INLINE static uint32_t Sha1RoundFunction(uint32_t b, uint32_t c,
                                                uint32_t d, uint8_t mode) {
  switch (UAnd8(mode, 3_u8)) {
    case 0:
      return Sha1Choose(b, c, d);
    case 1:
      return Sha1Parity(b, c, d);
    case 2:
      return Sha1Majority(b, c, d);
    default:
      return Sha1Parity(b, c, d);
  }
}

ALWAYS_INLINE static uint32_t Sha1RoundConstant(uint8_t mode) {
  switch (UAnd8(mode, 3_u8)) {
    case 0:
      return 0x5A827999_u32;
    case 1:
      return 0x6ED9EBA1_u32;
    case 2:
      return 0x8F1BBCDC_u32;
    default:
      return 0xCA62C1D6_u32;
  }
}

template <typename D, typename S1, typename S2>
DEF_SEM(SHA1RNDS4, D dst, S1 src1, S2 src2, I8 src3) {
  auto state_vec = UReadV32(src1);
  auto message_vec = UReadV32(src2);
  auto mode = Read(src3);
  auto constant = Sha1RoundConstant(mode);

  auto a = UExtractV32(state_vec, 3);
  auto b = UExtractV32(state_vec, 2);
  auto c = UExtractV32(state_vec, 1);
  auto d = UExtractV32(state_vec, 0);
  auto e = 0_u32;

#define SHA1RNDS4_ROUND(message_index) \
  do { \
    auto temp = UAdd(UAdd(UAdd(ShaRol32(a, 5_u32), \
                               Sha1RoundFunction(b, c, d, mode)), \
                          e), \
                     UAdd(UExtractV32(message_vec, message_index), constant)); \
    e = d; \
    d = c; \
    c = ShaRor32(b, 2_u32); \
    b = a; \
    a = temp; \
  } while (false)

  SHA1RNDS4_ROUND(3);
  SHA1RNDS4_ROUND(2);
  SHA1RNDS4_ROUND(1);
  SHA1RNDS4_ROUND(0);

#undef SHA1RNDS4_ROUND

  auto dst_vec = UClearV32(UReadV32(dst));
  dst_vec = UInsertV32(dst_vec, 0, d);
  dst_vec = UInsertV32(dst_vec, 1, c);
  dst_vec = UInsertV32(dst_vec, 2, b);
  dst_vec = UInsertV32(dst_vec, 3, a);
  UWriteV32(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(SHA1RNDS4_XMMi32_XMMi32_IMM8_SHA) = SHA1RNDS4<V128W, V128, V128>;
DEF_ISEL(SHA1RNDS4_XMMi32_MEMi32_IMM8_SHA) = SHA1RNDS4<V128W, V128, MV128>;

namespace {

ALWAYS_INLINE static uint32_t Sha256SmallSigma0(uint32_t value) {
  return UXor(UXor(ShaRor32(value, 7_u32), ShaRor32(value, 18_u32)),
              UShr(value, 3_u32));
}

ALWAYS_INLINE static uint32_t Sha256SmallSigma1(uint32_t value) {
  return UXor(UXor(ShaRor32(value, 17_u32), ShaRor32(value, 19_u32)),
              UShr(value, 10_u32));
}

template <typename D, typename S1, typename S2>
DEF_SEM(SHA256MSG1, D dst, S1 src1, S2 src2) {
  auto src1_vec = UReadV32(src1);
  auto src2_vec = UReadV32(src2);
  auto dst_vec = UClearV32(UReadV32(dst));

  dst_vec = UInsertV32(
      dst_vec, 0,
      UAdd(UExtractV32(src1_vec, 0),
           Sha256SmallSigma0(UExtractV32(src1_vec, 1))));
  dst_vec = UInsertV32(
      dst_vec, 1,
      UAdd(UExtractV32(src1_vec, 1),
           Sha256SmallSigma0(UExtractV32(src1_vec, 2))));
  dst_vec = UInsertV32(
      dst_vec, 2,
      UAdd(UExtractV32(src1_vec, 2),
           Sha256SmallSigma0(UExtractV32(src1_vec, 3))));
  dst_vec = UInsertV32(
      dst_vec, 3,
      UAdd(UExtractV32(src1_vec, 3),
           Sha256SmallSigma0(UExtractV32(src2_vec, 0))));

  UWriteV32(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(SHA256MSG2, D dst, S1 src1, S2 src2) {
  auto src1_vec = UReadV32(src1);
  auto src2_vec = UReadV32(src2);

  auto word0 = UAdd(UExtractV32(src1_vec, 0),
                    Sha256SmallSigma1(UExtractV32(src2_vec, 2)));
  auto word1 = UAdd(UExtractV32(src1_vec, 1),
                    Sha256SmallSigma1(UExtractV32(src2_vec, 3)));
  auto word2 = UAdd(UExtractV32(src1_vec, 2), Sha256SmallSigma1(word0));
  auto word3 = UAdd(UExtractV32(src1_vec, 3), Sha256SmallSigma1(word1));

  auto dst_vec = UClearV32(UReadV32(dst));
  dst_vec = UInsertV32(dst_vec, 0, word0);
  dst_vec = UInsertV32(dst_vec, 1, word1);
  dst_vec = UInsertV32(dst_vec, 2, word2);
  dst_vec = UInsertV32(dst_vec, 3, word3);
  UWriteV32(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(SHA256MSG1_XMMi32_XMMi32_SHA) = SHA256MSG1<V128W, V128, V128>;
DEF_ISEL(SHA256MSG1_XMMi32_MEMi32_SHA) = SHA256MSG1<V128W, V128, MV128>;
DEF_ISEL(SHA256MSG2_XMMi32_XMMi32_SHA) = SHA256MSG2<V128W, V128, V128>;
DEF_ISEL(SHA256MSG2_XMMi32_MEMi32_SHA) = SHA256MSG2<V128W, V128, MV128>;

namespace {

ALWAYS_INLINE static uint32_t Sha256BigSigma0(uint32_t value) {
  return UXor(UXor(ShaRor32(value, 2_u32), ShaRor32(value, 13_u32)),
              ShaRor32(value, 22_u32));
}

ALWAYS_INLINE static uint32_t Sha256BigSigma1(uint32_t value) {
  return UXor(UXor(ShaRor32(value, 6_u32), ShaRor32(value, 11_u32)),
              ShaRor32(value, 25_u32));
}

template <typename D, typename S1, typename S2>
DEF_SEM(SHA256RNDS2, D dst, S1 src1, S2 src2) {
  auto cdgh_vec = UReadV32(src1);
  auto abef_vec = UReadV32(src2);
  auto message_vec = state.vec[0].xmm.dwords;

  auto a = UExtractV32(abef_vec, 3);
  auto b = UExtractV32(abef_vec, 2);
  auto e = UExtractV32(abef_vec, 1);
  auto f = UExtractV32(abef_vec, 0);
  auto c = UExtractV32(cdgh_vec, 3);
  auto d = UExtractV32(cdgh_vec, 2);
  auto g = UExtractV32(cdgh_vec, 1);
  auto h = UExtractV32(cdgh_vec, 0);

#define SHA256RNDS2_ROUND(message_index) \
  do { \
    auto t1 = UAdd( \
        UAdd(UAdd(h, Sha256BigSigma1(e)), Sha1Choose(e, f, g)), \
        UExtractV32(message_vec, message_index)); \
    auto t2 = UAdd(Sha256BigSigma0(a), Sha1Majority(a, b, c)); \
    h = g; \
    g = f; \
    f = e; \
    e = UAdd(d, t1); \
    d = c; \
    c = b; \
    b = a; \
    a = UAdd(t1, t2); \
  } while (false)

  SHA256RNDS2_ROUND(0);
  SHA256RNDS2_ROUND(1);

#undef SHA256RNDS2_ROUND

  auto dst_vec = UClearV32(UReadV32(dst));
  dst_vec = UInsertV32(dst_vec, 0, f);
  dst_vec = UInsertV32(dst_vec, 1, e);
  dst_vec = UInsertV32(dst_vec, 2, b);
  dst_vec = UInsertV32(dst_vec, 3, a);
  UWriteV32(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(SHA256RNDS2_XMMi32_XMMi32_SHA) = SHA256RNDS2<V128W, V128, V128>;
DEF_ISEL(SHA256RNDS2_XMMi32_MEMi32_SHA) = SHA256RNDS2<V128W, V128, MV128>;
