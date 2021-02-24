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

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(PUNPCKHBW, D dst, S1 src1, S2 src2) {
  auto src1_vec = UReadV8(src1);
  auto src2_vec = UReadV8(src2);
  auto dst_vec = UClearV8(UReadV8(dst));
  auto num_elems = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0, j = num_elems; i < (num_elems / 2);
                         ++i, j -= 2) {
    dst_vec =
        UInsertV8(dst_vec, j - 1, UExtractV8(src2_vec, (num_elems - 1) - i));
    dst_vec =
        UInsertV8(dst_vec, j - 2, UExtractV8(src1_vec, (num_elems - 1) - i));
  }
  UWriteV8(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PUNPCKHWD, D dst, S1 src1, S2 src2) {
  auto src1_vec = UReadV16(src1);
  auto src2_vec = UReadV16(src2);
  auto dst_vec = UClearV16(UReadV16(dst));
  auto num_elems = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0, j = num_elems; i < (num_elems / 2);
                         ++i, j -= 2) {
    dst_vec =
        UInsertV16(dst_vec, j - 1, UExtractV16(src2_vec, (num_elems - 1) - i));
    dst_vec =
        UInsertV16(dst_vec, j - 2, UExtractV16(src1_vec, (num_elems - 1) - i));
  }
  UWriteV16(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PUNPCKHDQ, D dst, S1 src1, S2 src2) {
  auto src1_vec = UReadV32(src1);
  auto src2_vec = UReadV32(src2);
  auto dst_vec = UClearV32(UReadV32(dst));
  auto num_elems = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0, j = num_elems; i < (num_elems / 2);
                         ++i, j -= 2) {
    dst_vec =
        UInsertV32(dst_vec, j - 1, UExtractV32(src2_vec, (num_elems - 1) - i));
    dst_vec =
        UInsertV32(dst_vec, j - 2, UExtractV32(src1_vec, (num_elems - 1) - i));
  }
  UWriteV32(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PUNPCKHQDQ, D dst, S1 src1, S2 src2) {
  auto src1_vec = UReadV64(src1);
  auto src2_vec = UReadV64(src2);
  auto dst_vec = UClearV64(UReadV64(dst));
  auto num_elems = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0, j = num_elems; i < (num_elems / 2);
                         ++i, j -= 2) {
    dst_vec =
        UInsertV64(dst_vec, j - 1, UExtractV64(src2_vec, (num_elems - 1) - i));
    dst_vec =
        UInsertV64(dst_vec, j - 2, UExtractV64(src1_vec, (num_elems - 1) - i));
  }
  UWriteV64(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PUNPCKLBW, D dst, S1 src1, S2 src2) {
  auto src1_vec = UReadV8(src1);
  auto src2_vec = UReadV8(src2);
  auto dst_vec = UClearV8(UReadV8(dst));
  auto num_elems = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0, j = 0; i < (num_elems / 2);
                         ++i, j += 2) {
    dst_vec = UInsertV8(dst_vec, j, UExtractV8(src1_vec, i));
    dst_vec = UInsertV8(dst_vec, j + 1, UExtractV8(src2_vec, i));
  }
  UWriteV8(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PUNPCKLWD, D dst, S1 src1, S2 src2) {
  auto src1_vec = UReadV16(src1);
  auto src2_vec = UReadV16(src2);
  auto dst_vec = UClearV16(UReadV16(dst));
  auto num_elems = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0, j = 0; i < (num_elems / 2);
                         ++i, j += 2) {
    dst_vec = UInsertV16(dst_vec, j, UExtractV16(src1_vec, i));
    dst_vec = UInsertV16(dst_vec, j + 1, UExtractV16(src2_vec, i));
  }
  UWriteV16(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PUNPCKLDQ, D dst, S1 src1, S2 src2) {
  auto src1_vec = UReadV32(src1);
  auto src2_vec = UReadV32(src2);
  auto dst_vec = UClearV32(UReadV32(dst));
  auto num_elems = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0, j = 0; i < (num_elems / 2);
                         ++i, j += 2) {
    dst_vec = UInsertV32(dst_vec, j, UExtractV32(src1_vec, i));
    dst_vec = UInsertV32(dst_vec, j + 1, UExtractV32(src2_vec, i));
  }
  UWriteV32(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PUNPCKLQDQ, D dst, S1 src1, S2 src2) {
  auto src1_vec = UReadV64(src1);
  auto src2_vec = UReadV64(src2);
  auto dst_vec = UClearV64(UReadV64(dst));
  auto num_elems = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0, j = 0; i < (num_elems / 2);
                         ++i, j += 2) {
    dst_vec = UInsertV64(dst_vec, j, UExtractV64(src1_vec, i));
    dst_vec = UInsertV64(dst_vec, j + 1, UExtractV64(src2_vec, i));
  }
  UWriteV64(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(PUNPCKHBW_MMXq_MEMq) = PUNPCKHBW<V64W, V64, MV64>;
DEF_ISEL(PUNPCKHBW_MMXq_MMXd) = PUNPCKHBW<V64W, V64, V64>;
DEF_ISEL(PUNPCKHBW_XMMdq_MEMdq) = PUNPCKHBW<V128W, V128, MV128>;
DEF_ISEL(PUNPCKHBW_XMMdq_XMMq) = PUNPCKHBW<V128W, V128, V128>;

DEF_ISEL(PUNPCKHWD_MMXq_MEMq) = PUNPCKHWD<V64W, V64, MV64>;
DEF_ISEL(PUNPCKHWD_MMXq_MMXd) = PUNPCKHWD<V64W, V64, V64>;
DEF_ISEL(PUNPCKHWD_XMMdq_MEMdq) = PUNPCKHWD<V128W, V128, MV128>;
DEF_ISEL(PUNPCKHWD_XMMdq_XMMq) = PUNPCKHWD<V128W, V128, V128>;

DEF_ISEL(PUNPCKHDQ_MMXq_MEMq) = PUNPCKHDQ<V64W, V64, MV64>;
DEF_ISEL(PUNPCKHDQ_MMXq_MMXd) = PUNPCKHDQ<V64W, V64, V64>;
DEF_ISEL(PUNPCKHDQ_XMMdq_MEMdq) = PUNPCKHDQ<V128W, V128, MV128>;
DEF_ISEL(PUNPCKHDQ_XMMdq_XMMq) = PUNPCKHDQ<V128W, V128, V128>;

DEF_ISEL(PUNPCKHQDQ_XMMdq_MEMdq) = PUNPCKHQDQ<V128W, V128, MV128>;
DEF_ISEL(PUNPCKHQDQ_XMMdq_XMMq) = PUNPCKHQDQ<V128W, V128, V128>;

DEF_ISEL(PUNPCKLBW_MMXq_MEMd) = PUNPCKLBW<V64W, V64, MV32>;
DEF_ISEL(PUNPCKLBW_MMXq_MMXd) = PUNPCKLBW<V64W, V64, V64>;
DEF_ISEL(PUNPCKLBW_XMMdq_MEMdq) = PUNPCKLBW<V128W, V128, MV128>;
DEF_ISEL(PUNPCKLBW_XMMdq_XMMq) = PUNPCKLBW<V128W, V128, V128>;

DEF_ISEL(PUNPCKLWD_MMXq_MEMd) = PUNPCKLWD<V64W, V64, MV32>;
DEF_ISEL(PUNPCKLWD_MMXq_MMXd) = PUNPCKLWD<V64W, V64, V64>;
DEF_ISEL(PUNPCKLWD_XMMdq_MEMdq) = PUNPCKLWD<V128W, V128, MV128>;
DEF_ISEL(PUNPCKLWD_XMMdq_XMMq) = PUNPCKLWD<V128W, V128, V128>;

DEF_ISEL(PUNPCKLDQ_MMXq_MEMd) = PUNPCKLDQ<V64W, V64, MV32>;
DEF_ISEL(PUNPCKLDQ_MMXq_MMXd) = PUNPCKLDQ<V64W, V64, V64>;
DEF_ISEL(PUNPCKLDQ_XMMdq_MEMdq) = PUNPCKLDQ<V128W, V128, MV128>;
DEF_ISEL(PUNPCKLDQ_XMMdq_XMMq) = PUNPCKLDQ<V128W, V128, V128>;

DEF_ISEL(PUNPCKLQDQ_XMMdq_MEMdq) = PUNPCKLQDQ<V128W, V128, MV128>;
DEF_ISEL(PUNPCKLQDQ_XMMdq_XMMq) = PUNPCKLQDQ<V128W, V128, V128>;

// Adding new MMX Instructions
namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(PADDB, D dst, S1 src1, S2 src2) {
  auto lhs_vec = UReadV8(src1);
  auto rhs_vec = UReadV8(src2);
  auto dst_vec = UAddV8(lhs_vec, rhs_vec);
  UWriteV8(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PADDW, D dst, S1 src1, S2 src2) {
  auto lhs_vec = UReadV16(src1);
  auto rhs_vec = UReadV16(src2);
  auto dst_vec = UAddV16(lhs_vec, rhs_vec);
  UWriteV16(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PADDD, D dst, S1 src1, S2 src2) {
  auto lhs_vec = UReadV32(src1);
  auto rhs_vec = UReadV32(src2);
  auto dst_vec = UAddV32(lhs_vec, rhs_vec);
  UWriteV32(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PADDQ, D dst, S1 src1, S2 src2) {
  auto lhs_vec = UReadV64(src1);
  auto rhs_vec = UReadV64(src2);
  auto dst_vec = UAddV64(lhs_vec, rhs_vec);
  UWriteV64(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(PADDB_MMXq_MMXq) = PADDB<V64W, V64, V64>;
DEF_ISEL(PADDB_MMXq_MEMq) = PADDB<V64W, V64, MV64>;
DEF_ISEL(PADDB_XMMdq_XMMdq) = PADDB<V128W, V128, V128>;
DEF_ISEL(PADDB_XMMdq_MEMdq) = PADDB<V128W, V128, MV128>;

DEF_ISEL(PADDW_MMXq_MMXq) = PADDW<V64W, V64, V64>;
DEF_ISEL(PADDW_MMXq_MEMq) = PADDW<V64W, V64, MV64>;
DEF_ISEL(PADDW_XMMdq_XMMdq) = PADDW<V128W, V128, V128>;
DEF_ISEL(PADDW_XMMdq_MEMdq) = PADDW<V128W, V128, MV128>;

DEF_ISEL(PADDD_MMXq_MMXq) = PADDD<V64W, V64, V64>;
DEF_ISEL(PADDD_MMXq_MEMq) = PADDD<V64W, V64, MV64>;
DEF_ISEL(PADDD_XMMdq_XMMdq) = PADDD<V128W, V128, V128>;
DEF_ISEL(PADDD_XMMdq_MEMdq) = PADDD<V128W, V128, MV128>;

DEF_ISEL(PADDQ_MMXq_MMXq) = PADDQ<V64W, V64, V64>;
DEF_ISEL(PADDQ_MMXq_MEMq) = PADDQ<V64W, V64, MV64>;
DEF_ISEL(PADDQ_XMMdq_XMMdq) = PADDQ<V128W, V128, V128>;
DEF_ISEL(PADDQ_XMMdq_MEMdq) = PADDQ<V128W, V128, MV128>;
IF_AVX(DEF_ISEL(VPADDQ_XMMdq_XMMdq_XMMdq) = PADDQ<VV128W, V128, V128>;)
IF_AVX(DEF_ISEL(VPADDQ_XMMdq_XMMdq_MEMdq) = PADDQ<VV128W, V128, MV128>;)
IF_AVX(DEF_ISEL(VPADDQ_YMMqq_YMMqq_MEMqq) = PADDQ<VV256W, VV256, MV256>;)
IF_AVX(DEF_ISEL(VPADDQ_YMMqq_YMMqq_YMMqq) = PADDQ<VV256W, VV256, VV256>;)

/*
5255 VPADDQ VPADDQ_ZMMu64_MASKmskw_ZMMu64_ZMMu64_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
5256 VPADDQ VPADDQ_ZMMu64_MASKmskw_ZMMu64_MEMu64_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5257 VPADDQ VPADDQ_XMMu64_MASKmskw_XMMu64_XMMu64_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
5258 VPADDQ VPADDQ_XMMu64_MASKmskw_XMMu64_MEMu64_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5259 VPADDQ VPADDQ_YMMu64_MASKmskw_YMMu64_YMMu64_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
5260 VPADDQ VPADDQ_YMMu64_MASKmskw_YMMu64_MEMu64_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
*/

/*
 * signed saturation arithematic for PADDS
 * int8 res = a + b;
 * int8 tmp = (res & ~(a | b)) < 0 ? 0x7f : res;
 * int8 c = (~res & (a & b)) < 0 ? 0x80 : tmp;
 *
 */

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(PADDSB, D dst, S1 src1, S2 src2) {
  auto src1_vec = SReadV8(src1);
  auto src2_vec = SReadV8(src2);
  auto dst_vec = SClearV8(SReadV8(dst));

  // Compute signed saturation arithematic on each bytes
  _Pragma("unroll") for (size_t index = 0; index < NumVectorElems(src1_vec);
                         index++) {
    auto v1 = SExtractV8(src1_vec, index);
    auto v2 = SExtractV8(src2_vec, index);
    auto max = SExt(Maximize(v1));
    auto min = SExt(Minimize(v1));
    auto sum = SAdd(SExt(v1), SExt(v2));
    auto upper_limit = Select(SCmpLt(sum, max), sum, max);
    auto lower_limit = Select(SCmpGte(sum, min), sum, min);
    sum = Select(SCmpLt(sum, decltype(sum)(0)), lower_limit, upper_limit);
    dst_vec = SInsertV8(dst_vec, index, Trunc(sum));
  }
  SWriteV8(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PADDSW, D dst, S1 src1, S2 src2) {
  auto src1_vec = SReadV16(src1);
  auto src2_vec = SReadV16(src2);

  // Compute signed saturation arithematic on each bytes
  auto dst_vec = SClearV16(SReadV16(dst));
  _Pragma("unroll") for (size_t index = 0; index < NumVectorElems(src1_vec);
                         index++) {
    auto v1 = SExtractV16(src1_vec, index);
    auto v2 = SExtractV16(src2_vec, index);
    auto max = SExt(Maximize(v1));
    auto min = SExt(Minimize(v1));
    auto sum = SAdd(SExt(v1), SExt(v2));
    auto upper_limit = Select(SCmpLt(sum, max), sum, max);
    auto lower_limit = Select(SCmpGte(sum, min), sum, min);
    sum = Select(SCmpLt(sum, decltype(sum)(0)), lower_limit, upper_limit);
    dst_vec = SInsertV16(dst_vec, index, Trunc(sum));
  }
  SWriteV16(dst, dst_vec);
  return memory;
}
}  // namespace

DEF_ISEL(PADDSB_MMXq_MMXq) = PADDSB<V64W, V64, V64>;
DEF_ISEL(PADDSB_MMXq_MEMq) = PADDSB<V64W, V64, MV64>;
DEF_ISEL(PADDSB_XMMdq_XMMdq) = PADDSB<V128W, V128, V128>;
DEF_ISEL(PADDSB_XMMdq_MEMdq) = PADDSB<V128W, V128, MV128>;

DEF_ISEL(PADDSW_MMXq_MMXq) = PADDSW<V64W, V64, V64>;
DEF_ISEL(PADDSW_MMXq_MEMq) = PADDSW<V64W, V64, MV64>;
DEF_ISEL(PADDSW_XMMdq_XMMdq) = PADDSW<V128W, V128, V128>;
DEF_ISEL(PADDSW_XMMdq_MEMdq) = PADDSW<V128W, V128, MV128>;

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(PADDUSB, D dst, S1 src1, S2 src2) {
  auto src1_vec = UReadV8(src1);
  auto src2_vec = UReadV8(src2);
  auto dst_vec = UClearV8(UReadV8(dst));
  auto num_groups = NumVectorElems(dst_vec);

  // Compute unsigned saturation arithematic on each bytes
  _Pragma("unroll") for (size_t i = 0; i < num_groups; ++i) {
    auto v1 = UExtractV8(src1_vec, i);
    auto v2 = UExtractV8(src2_vec, i);
    uint8_t v_sum = v1 + v2;
    v_sum = Select(v_sum < v1, static_cast<uint8_t>(-1), v_sum);
    dst_vec.elems[i] = v_sum;
  }
  UWriteV8(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PADDUSW, D dst, S1 src1, S2 src2) {
  auto src1_vec = UReadV16(src1);
  auto src2_vec = UReadV16(src2);
  auto dst_vec = UClearV16(UReadV16(dst));
  auto num_groups = NumVectorElems(dst_vec);

  // Compute unsigned saturation arithematic on each words
  _Pragma("unroll") for (size_t i = 0; i < num_groups; ++i) {
    auto v1 = UExtractV16(src1_vec, i);
    auto v2 = UExtractV16(src2_vec, i);
    uint16_t v_sum = v1 + v2;
    v_sum = Select(v_sum < v1, static_cast<uint16_t>(-1), v_sum);
    dst_vec.elems[i] = v_sum;
  }
  UWriteV16(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(PADDUSB_XMMdq_XMMdq) = PADDUSB<V128W, V128, V128>;
DEF_ISEL(PADDUSB_XMMdq_MEMdq) = PADDUSB<V128W, V128, MV128>;

DEF_ISEL(PADDUSW_XMMdq_XMMdq) = PADDUSW<V128W, V128, V128>;
DEF_ISEL(PADDUSW_XMMdq_MEMdq) = PADDUSW<V128W, V128, MV128>;

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(PHADDW, D dst, S1 src1, S2 src2) {
  auto lhs_vec = SReadV16(src1);
  auto rhs_vec = SReadV16(src2);
  auto dst_vec = SClearV16(SReadV16(dst));

  // Compute the horizontal packing
  auto vec_count = NumVectorElems(lhs_vec);
  _Pragma("unroll") for (size_t index = 0; index < vec_count; index += 2) {
    auto v1 = SExtractV16(lhs_vec, index);
    auto v2 = SExtractV16(lhs_vec, index + 1);
    auto i = UDiv(UInt32(index), UInt32(2));
    dst_vec = SInsertV16(dst_vec, i, SAdd(v1, v2));
  }
  _Pragma("unroll") for (size_t index = 0; index < NumVectorElems(rhs_vec);
                         index += 2) {
    auto v1 = SExtractV16(rhs_vec, index);
    auto v2 = SExtractV16(rhs_vec, index + 1);
    auto i = UAdd(UInt32(index), UInt32(vec_count));
    i = UDiv(i, 2);
    dst_vec = SInsertV16(dst_vec, i, SAdd(v1, v2));
  }
  SWriteV16(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PHADDD, D dst, S1 src1, S2 src2) {
  auto lhs_vec = SReadV32(src1);
  auto rhs_vec = SReadV32(src2);
  auto dst_vec = SClearV32(SReadV32(dst));

  // Compute the horizontal packing
  auto vec_count = NumVectorElems(lhs_vec);
  _Pragma("unroll") for (size_t index = 0; index < vec_count; index += 2) {
    auto v1 = SExtractV32(lhs_vec, index);
    auto v2 = SExtractV32(lhs_vec, index + 1);
    auto i = UDiv(UInt32(index), UInt32(2));
    dst_vec = SInsertV32(dst_vec, i, SAdd(v1, v2));
  }
  _Pragma("unroll") for (size_t index = 0; index < NumVectorElems(rhs_vec);
                         index += 2) {
    auto v1 = SExtractV32(rhs_vec, index);
    auto v2 = SExtractV32(rhs_vec, index + 1);
    auto i = UDiv(UAdd(UInt32(index), UInt32(vec_count)), UInt32(2));
    dst_vec = SInsertV32(dst_vec, i, SAdd(v1, v2));
  }
  SWriteV32(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(PHADDW_MMXq_MMXq) = PHADDW<V64W, V64, V64>;
DEF_ISEL(PHADDW_MMXq_MEMq) = PHADDW<V64W, V64, MV64>;
DEF_ISEL(PHADDW_XMMdq_XMMdq) = PHADDW<V128W, V128, V128>;
DEF_ISEL(PHADDW_XMMdq_MEMdq) = PHADDW<V128W, V128, MV128>;

DEF_ISEL(PHADDD_MMXq_MMXq) = PHADDD<V64W, V64, V64>;
DEF_ISEL(PHADDD_MMXq_MEMq) = PHADDD<V64W, V64, MV64>;
DEF_ISEL(PHADDD_XMMdq_XMMdq) = PHADDD<V128W, V128, V128>;
DEF_ISEL(PHADDD_XMMdq_MEMdq) = PHADDD<V128W, V128, MV128>;

template <typename D, typename S1, typename S2>
DEF_SEM(PHADDSW, D dst, S1 src1, S2 src2) {
  auto src1_vec = SReadV16(src1);
  auto src2_vec = SReadV16(src2);
  auto dst_vec = SClearV16(SReadV16(dst));

  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t index = 0; index < vec_count; index += 2) {
    auto add_elem =
        SAdd(SExtractV16(src1_vec, index), SExtractV16(src1_vec, index + 1));
    auto or_elem =
        SOr(SExtractV16(src1_vec, index), SExtractV16(src1_vec, index + 1));
    auto and_elem =
        SAnd(SExtractV16(src1_vec, index), SExtractV16(src1_vec, index + 1));
    auto tmp =
        Select(SCmpLt(SAnd(add_elem, SNot(or_elem)), decltype(add_elem)(0)),
               Maximize(add_elem), add_elem);
    auto value =
        Select(SCmpLt(SAnd(SNot(add_elem), and_elem), decltype(add_elem)(0)),
               decltype(add_elem)(0x8000), tmp);
    dst_vec = SInsertV16(dst_vec, index / 2, value);
  }

  _Pragma("unroll") for (size_t index = 0; index < NumVectorElems(src2_vec);
                         index += 2) {
    auto add_elem =
        SAdd(SExtractV16(src2_vec, index), SExtractV16(src2_vec, index + 1));
    auto or_elem =
        SOr(SExtractV16(src2_vec, index), SExtractV16(src2_vec, index + 1));
    auto and_elem =
        SAnd(SExtractV16(src2_vec, index), SExtractV16(src2_vec, index + 1));
    auto tmp =
        Select(SCmpLt(SAnd(add_elem, SNot(or_elem)), decltype(add_elem)(0)),
               Maximize(add_elem), add_elem);
    auto value =
        Select(SCmpLt(SAnd(SNot(add_elem), and_elem), decltype(add_elem)(0)),
               decltype(add_elem)(0x8000), tmp);
    dst_vec = SInsertV16(dst_vec, (index + vec_count) / 2, value);
  }
  SWriteV16(dst, dst_vec);
  return memory;
}

DEF_ISEL(PHADDSW_MMXq_MMXq) = PHADDSW<V64W, V64, V64>;
DEF_ISEL(PHADDSW_MMXq_MEMq) = PHADDSW<V64W, V64, MV64>;
DEF_ISEL(PHADDSW_XMMdq_XMMdq) = PHADDSW<V128W, V128, V128>;
DEF_ISEL(PHADDSW_XMMdq_MEMdq) = PHADDSW<V128W, V128, MV128>;

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(PSUBB, D dst, S1 src1, S2 src2) {
  auto lhs_vec = SReadV8(src1);
  auto rhs_vec = SReadV8(src2);
  auto dst_vec = SSubV8(lhs_vec, rhs_vec);
  SWriteV8(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PSUBW, D dst, S1 src1, S2 src2) {
  auto lhs_vec = SReadV16(src1);
  auto rhs_vec = SReadV16(src2);
  auto dst_vec = SSubV16(lhs_vec, rhs_vec);
  SWriteV16(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PSUBD, D dst, S1 src1, S2 src2) {
  auto lhs_vec = SReadV32(src1);
  auto rhs_vec = SReadV32(src2);
  auto dst_vec = SSubV32(lhs_vec, rhs_vec);
  SWriteV32(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PSUBQ, D dst, S1 src1, S2 src2) {
  auto lhs_vec = SReadV64(src1);
  auto rhs_vec = SReadV64(src2);
  auto dst_vec = SSubV64(lhs_vec, rhs_vec);
  SWriteV64(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(PSUBB_MMXq_MMXq) = PSUBB<V64W, V64, V64>;
DEF_ISEL(PSUBB_MMXq_MEMq) = PSUBB<V64W, V64, MV64>;
DEF_ISEL(PSUBB_XMMdq_XMMdq) = PSUBB<V128W, V128, V128>;
DEF_ISEL(PSUBB_XMMdq_MEMdq) = PSUBB<V128W, V128, MV128>;

DEF_ISEL(PSUBW_MMXq_MMXq) = PSUBW<V64W, V64, V64>;
DEF_ISEL(PSUBW_MMXq_MEMq) = PSUBW<V64W, V64, MV64>;
DEF_ISEL(PSUBW_XMMdq_XMMdq) = PSUBW<V128W, V128, V128>;
DEF_ISEL(PSUBW_XMMdq_MEMdq) = PSUBW<V128W, V128, MV128>;

DEF_ISEL(PSUBD_MMXq_MMXq) = PSUBD<V64W, V64, V64>;
DEF_ISEL(PSUBD_MMXq_MEMq) = PSUBD<V64W, V64, MV64>;
DEF_ISEL(PSUBD_XMMdq_XMMdq) = PSUBD<V128W, V128, V128>;
DEF_ISEL(PSUBD_XMMdq_MEMdq) = PSUBD<V128W, V128, MV128>;
IF_AVX(DEF_ISEL(VPSUBD_XMMdq_XMMdq_MEMdq) = PSUBD<VV128W, V128, MV128>;)
IF_AVX(DEF_ISEL(VPSUBD_XMMdq_XMMdq_XMMdq) = PSUBD<VV128W, V128, V128>;)

DEF_ISEL(PSUBQ_MMXq_MMXq) = PSUBQ<V64W, V64, V64>;
DEF_ISEL(PSUBQ_MMXq_MEMq) = PSUBQ<V64W, V64, MV64>;
DEF_ISEL(PSUBQ_XMMdq_XMMdq) = PSUBQ<V128W, V128, V128>;
DEF_ISEL(PSUBQ_XMMdq_MEMdq) = PSUBQ<V128W, V128, MV128>;
IF_AVX(DEF_ISEL(VPSUBQ_XMMdq_XMMdq_MEMdq) = PSUBQ<VV128W, V128, MV128>;)
IF_AVX(DEF_ISEL(VPSUBQ_XMMdq_XMMdq_XMMdq) = PSUBQ<VV128W, V128, V128>;)

/*
3305 VPSUBD VPSUBD_YMMqq_YMMqq_MEMqq AVX2 AVX2 AVX2 ATTRIBUTES:
3305 VPSUBD VPSUBD_YMMqq_YMMqq_MEMqq AVX2 AVX2 AVX2 ATTRIBUTES:

3322 VPSUBQ VPSUBQ_YMMqq_YMMqq_MEMqq AVX2 AVX2 AVX2 ATTRIBUTES:
3323 VPSUBQ VPSUBQ_YMMqq_YMMqq_YMMqq AVX2 AVX2 AVX2 ATTRIBUTES:
*/

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(PSUBUSB, D dst, S1 src1, S2 src2) {
  auto lhs_vec = UReadV8(src1);
  auto rhs_vec = UReadV8(src2);
  auto dst_vec = UClearV8(UReadV8(dst));

  _Pragma("unroll") for (size_t i = 0; i < NumVectorElems(dst_vec); i++) {
    auto v1 = UExtractV8(lhs_vec, i);
    auto v2 = UExtractV8(rhs_vec, i);
    auto sub = USub(v1, v2);
    auto sub_val = Select(UCmpGt(v1, v2), sub, Minimize(v1));
    dst_vec = UInsertV8(dst_vec, i, sub_val);
  }
  UWriteV8(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PSUBUSW, D dst, S1 src1, S2 src2) {
  auto lhs_vec = UReadV16(src1);
  auto rhs_vec = UReadV16(src2);
  auto dst_vec = UClearV16(UReadV16(dst));

  _Pragma("unroll") for (size_t i = 0; i < NumVectorElems(dst_vec); i++) {
    auto v1 = UExtractV16(lhs_vec, i);
    auto v2 = UExtractV16(rhs_vec, i);
    auto sub = USub(v1, v2);
    auto sub_val = Select(UCmpGt(v1, v2), sub, Minimize(v1));
    dst_vec = UInsertV16(dst_vec, i, sub_val);
  }
  UWriteV16(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(PSUBUSB_MMXq_MMXq) = PSUBUSB<V64W, V64, V64>;
DEF_ISEL(PSUBUSB_MMXq_MEMq) = PSUBUSB<V64W, V64, MV64>;
DEF_ISEL(PSUBUSB_XMMdq_XMMdq) = PSUBUSB<V128W, V128, V128>;
DEF_ISEL(PSUBUSB_XMMdq_MEMdq) = PSUBUSB<V128W, V128, MV128>;

DEF_ISEL(PSUBUSW_MMXq_MMXq) = PSUBUSW<V64W, V64, V64>;
DEF_ISEL(PSUBUSW_MMXq_MEMq) = PSUBUSW<V64W, V64, MV64>;
DEF_ISEL(PSUBUSW_XMMdq_XMMdq) = PSUBUSW<V128W, V128, V128>;
DEF_ISEL(PSUBUSW_XMMdq_MEMdq) = PSUBUSW<V128W, V128, MV128>;

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(PAVGB, D dst, S1 src1, S2 src2) {
  auto lhs_vec = UReadV8(src1);
  auto rhs_vec = UReadV8(src2);
  auto dst_vec = UClearV8(UReadV8(dst));

  // Compute the AVG; The sum can spill to 9th bits
  auto vec_count = NumVectorElems(lhs_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto v1 = UExtractV8(lhs_vec, i);
    auto v2 = UExtractV8(rhs_vec, i);
    auto sum_elem = UAdd(ZExt(v1), ZExt(v2));
    auto sum = UAdd(sum_elem, decltype(sum_elem)(1));
    dst_vec = UInsertV8(dst_vec, i, UInt8(UShr(sum, decltype(sum)(1))));
  }
  UWriteV8(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PAVGW, D dst, S1 src1, S2 src2) {
  auto lhs_vec = UReadV16(src1);
  auto rhs_vec = UReadV16(src2);
  auto dst_vec = UClearV16(UReadV16(dst));

  // Compute the AVG; The sum can spill to 17th bits
  auto vec_count = NumVectorElems(lhs_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto v1 = ZExt(UExtractV16(lhs_vec, i));
    auto v2 = ZExt(UExtractV16(rhs_vec, i));
    auto sum_elem = UAdd(v1, v2);
    auto sum = UAdd(sum_elem, decltype(sum_elem)(1));
    dst_vec = UInsertV16(dst_vec, i, Trunc(UShr(sum, decltype(sum)(1))));
  }
  UWriteV16(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(PAVGB_MMXq_MMXq) = PAVGB<V64W, V64, V64>;
DEF_ISEL(PAVGB_MMXq_MEMq) = PAVGB<V64W, V64, MV64>;
DEF_ISEL(PAVGB_XMMdq_XMMdq) = PAVGB<V128W, V128, V128>;
DEF_ISEL(PAVGB_XMMdq_MEMdq) = PAVGB<V128W, V128, MV128>;

DEF_ISEL(PAVGW_MMXq_MMXq) = PAVGW<V64W, V64, V64>;
DEF_ISEL(PAVGW_MMXq_MEMq) = PAVGW<V64W, V64, MV64>;
DEF_ISEL(PAVGW_XMMdq_XMMdq) = PAVGW<V128W, V128, V128>;
DEF_ISEL(PAVGW_XMMdq_MEMdq) = PAVGW<V128W, V128, MV128>;

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(PHSUBW, D dst, S1 src1, S2 src2) {
  auto lhs_vec = SReadV16(src1);
  auto rhs_vec = SReadV16(src2);
  auto dst_vec = SClearV16(SReadV16(dst));
  auto vec_count = NumVectorElems(lhs_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i = i + 2) {
    auto v1 = SExtractV16(lhs_vec, i);
    auto v2 = SExtractV16(lhs_vec, i + 1);
    auto index = UDiv(UInt32(i), UInt32(2));
    dst_vec = SInsertV16(dst_vec, index, SSub(v1, v2));
  }
  _Pragma("unroll") for (size_t i = 0; i < NumVectorElems(rhs_vec); i = i + 2) {
    auto v1 = SExtractV16(rhs_vec, i);
    auto v2 = SExtractV16(rhs_vec, i + 1);
    auto index = UDiv(UAdd(UInt32(i), UInt32(vec_count)), UInt32(2));
    dst_vec = SInsertV16(dst_vec, index, SSub(v1, v2));
  }
  SWriteV16(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PHSUBD, D dst, S1 src1, S2 src2) {
  auto lhs_vec = SReadV32(src1);
  auto rhs_vec = SReadV32(src2);
  auto dst_vec = SClearV32(SReadV32(dst));
  auto vec_count = NumVectorElems(lhs_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i = i + 2) {
    dst_vec =
        SInsertV32(dst_vec, i / 2,
                   SSub(SExtractV32(lhs_vec, i), SExtractV32(lhs_vec, i + 1)));
  }
  _Pragma("unroll") for (size_t i = 0; i < NumVectorElems(rhs_vec); i = i + 2) {
    dst_vec =
        SInsertV32(dst_vec, (i + vec_count) / 2,
                   SSub(SExtractV32(rhs_vec, i), SExtractV32(rhs_vec, i + 1)));
  }
  SWriteV32(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(PHSUBW_MMXq_MMXq) = PHSUBW<V64W, V64, V64>;
DEF_ISEL(PHSUBW_MMXq_MEMq) = PHSUBW<V64W, V64, MV64>;
DEF_ISEL(PHSUBW_XMMdq_XMMdq) = PHSUBW<V128W, V128, V128>;
DEF_ISEL(PHSUBW_XMMdq_MEMdq) = PHSUBW<V128W, V128, MV128>;

DEF_ISEL(PHSUBD_MMXq_MMXq) = PHSUBD<V64W, V64, V64>;
DEF_ISEL(PHSUBD_MMXq_MEMq) = PHSUBD<V64W, V64, MV64>;
DEF_ISEL(PHSUBD_XMMdq_XMMdq) = PHSUBD<V128W, V128, V128>;
DEF_ISEL(PHSUBD_XMMdq_MEMdq) = PHSUBD<V128W, V128, MV128>;

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(PMAXSW, D dst, S1 src1, S2 src2) {
  auto lhs_vec = SReadV16(src1);
  auto rhs_vec = SReadV16(src2);
  auto dst_vec = SClearV16(SReadV16(dst));

  // Compute MAX of words
  auto vec_count = NumVectorElems(lhs_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto max = Select(SCmpGt(SExtractV16(lhs_vec, i), SExtractV16(rhs_vec, i)),
                      SExtractV16(lhs_vec, i), SExtractV16(rhs_vec, i));
    dst_vec = SInsertV16(dst_vec, i, max);
  }
  SWriteV16(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(PMAXSW_MMXq_MMXq) = PMAXSW<V64W, V64, V64>;
DEF_ISEL(PMAXSW_MMXq_MEMq) = PMAXSW<V64W, V64, MV64>;
DEF_ISEL(PMAXSW_XMMdq_XMMdq) = PMAXSW<V128W, V128, V128>;
DEF_ISEL(PMAXSW_XMMdq_MEMdq) = PMAXSW<V128W, V128, MV128>;

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(PMAXUB, D dst, S1 src1, S2 src2) {
  auto lhs_vec = UReadV8(src1);
  auto rhs_vec = UReadV8(src2);
  auto dst_vec = UClearV8(UReadV8(dst));

  // Compute MAX of bytes
  auto vec_count = NumVectorElems(lhs_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto max = Select(UCmpGt(UExtractV8(lhs_vec, i), UExtractV8(rhs_vec, i)),
                      UExtractV8(lhs_vec, i), UExtractV8(rhs_vec, i));
    dst_vec = UInsertV8(dst_vec, i, max);
  }
  UWriteV8(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(PMAXUB_MMXq_MMXq) = PMAXUB<V64W, V64, V64>;
DEF_ISEL(PMAXUB_MMXq_MEMq) = PMAXUB<V64W, V64, MV64>;
DEF_ISEL(PMAXUB_XMMdq_XMMdq) = PMAXUB<V128W, V128, V128>;
DEF_ISEL(PMAXUB_XMMdq_MEMdq) = PMAXUB<V128W, V128, MV128>;

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(PMINSW, D dst, S1 src1, S2 src2) {
  auto lhs_vec = SReadV16(src1);
  auto rhs_vec = SReadV16(src2);
  auto dst_vec = SClearV16(SReadV16(dst));

  // Compute MIN of words
  auto vec_count = NumVectorElems(lhs_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto max = Select(SCmpLt(SExtractV16(lhs_vec, i), SExtractV16(rhs_vec, i)),
                      SExtractV16(lhs_vec, i), SExtractV16(rhs_vec, i));
    dst_vec = SInsertV16(dst_vec, i, max);
  }
  SWriteV16(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(PMINSW_MMXq_MMXq) = PMINSW<V64W, V64, V64>;
DEF_ISEL(PMINSW_MMXq_MEMq) = PMINSW<V64W, V64, MV64>;
DEF_ISEL(PMINSW_XMMdq_XMMdq) = PMINSW<V128W, V128, V128>;
DEF_ISEL(PMINSW_XMMdq_MEMdq) = PMINSW<V128W, V128, MV128>;

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(PMINUB, D dst, S1 src1, S2 src2) {
  auto lhs_vec = UReadV8(src1);
  auto rhs_vec = UReadV8(src2);
  auto dst_vec = UClearV8(UReadV8(dst));

  // Compute MIN of bytes
  auto vec_count = NumVectorElems(lhs_vec);

  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto max = Select(UCmpLt(UExtractV8(lhs_vec, i), UExtractV8(rhs_vec, i)),
                      UExtractV8(lhs_vec, i), UExtractV8(rhs_vec, i));
    dst_vec = UInsertV8(dst_vec, i, max);
  }
  UWriteV8(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(PMINUB_MMXq_MMXq) = PMINUB<V64W, V64, V64>;
DEF_ISEL(PMINUB_MMXq_MEMq) = PMINUB<V64W, V64, MV64>;
DEF_ISEL(PMINUB_XMMdq_XMMdq) = PMINUB<V128W, V128, V128>;
DEF_ISEL(PMINUB_XMMdq_MEMdq) = PMINUB<V128W, V128, MV128>;

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(PMULHRSW, D dst, S1 src1, S2 src2) {
  auto lhs_vec = SReadV16(src1);
  auto rhs_vec = SReadV16(src2);
  auto dst_vec = SClearV16(SReadV16(dst));
  auto vec_count = NumVectorElems(lhs_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto mul =
        SMul(Int32(SExtractV16(lhs_vec, i)), Int32(SExtractV16(rhs_vec, i)));
    auto temp = SAdd(SShr(mul, decltype(mul)(14)), decltype(mul)(1));
    temp = SShr(temp, decltype(temp)(1));
    dst_vec = SInsertV16(dst_vec, i, Int16(temp));
  }
  SWriteV16(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(PMULHRSW_MMXq_MMXq) = PMULHRSW<V64W, V64, V64>;
DEF_ISEL(PMULHRSW_MMXq_MEMq) = PMULHRSW<V64W, V64, MV64>;
DEF_ISEL(PMULHRSW_XMMdq_XMMdq) = PMULHRSW<V128W, V128, V128>;
DEF_ISEL(PMULHRSW_XMMdq_MEMdq) = PMULHRSW<V128W, V128, MV128>;

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(PMADDWD, D dst, S1 src1, S2 src2) {
  auto lhs_vec = SReadV16(src1);
  auto rhs_vec = SReadV16(src2);
  auto dst_vec = SClearV32(SReadV32(dst));

  // Multiply and Add Packed Integers
  auto vec_count = NumVectorElems(lhs_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i += 2) {
    auto mul1 =
        SMul(Int32(SExtractV16(lhs_vec, i)), Int32(SExtractV16(rhs_vec, i)));
    auto mul2 = SMul(Int32(SExtractV16(lhs_vec, i + 1)),
                     Int32(SExtractV16(rhs_vec, i + 1)));
    dst_vec = SInsertV32(dst_vec, i / 2, SAdd(mul1, mul2));
  }
  SWriteV32(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(PMADDWD_MMXq_MMXq) = PMADDWD<V64W, V64, V64>;
DEF_ISEL(PMADDWD_MMXq_MEMq) = PMADDWD<V64W, V64, MV64>;
DEF_ISEL(PMADDWD_XMMdq_XMMdq) = PMADDWD<V128W, V128, V128>;
DEF_ISEL(PMADDWD_XMMdq_MEMdq) = PMADDWD<V128W, V128, MV128>;

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(PMADDUBSW, D dst, S1 src1, S2 src2) {
  auto lhs_vec = UReadV8(src1);
  auto rhs_vec = SReadV8(src2);
  auto dst_vec = SClearV16(SReadV16(dst));

  // Multiply and Add Packed Signed and Unsigned Bytes
  auto vec_count = NumVectorElems(lhs_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i += 2) {
    auto mul1 =
        SMul(Int16(UExtractV8(lhs_vec, i)), Int16(SExtractV8(rhs_vec, i)));
    auto mul2 = SMul(Int16(UExtractV8(lhs_vec, i + 1)),
                     Int16(SExtractV8(rhs_vec, i + 1)));
    auto add_elem = SAdd(mul2, mul1);
    auto or_elem = SOr(mul2, mul1);
    auto and_elem = SAnd(mul2, mul1);
    auto tmp =
        Select(SCmpLt(SAnd(add_elem, SNot(or_elem)), decltype(add_elem)(0)),
               decltype(add_elem)(0x7FFF), add_elem);
    auto value =
        Select(SCmpLt(SAnd(SNot(add_elem), and_elem), decltype(add_elem)(0)),
               decltype(add_elem)(0x8000), tmp);
    dst_vec = SInsertV16(dst_vec, i / 2, value);
  }
  SWriteV16(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(PMADDUBSW_MMXq_MMXq) = PMADDUBSW<V64W, V64, V64>;
DEF_ISEL(PMADDUBSW_MMXq_MEMq) = PMADDUBSW<V64W, V64, MV64>;
DEF_ISEL(PMADDUBSW_XMMdq_XMMdq) = PMADDUBSW<V128W, V128, V128>;
DEF_ISEL(PMADDUBSW_XMMdq_MEMdq) = PMADDUBSW<V128W, V128, MV128>;

namespace {

template <typename D, typename S1>
DEF_SEM(PABSB, D dst, S1 src1) {
  auto src_vec = SReadV8(src1);
  auto dst_vec = SClearV8(SReadV8(dst));
  auto vec_count = NumVectorElems(src_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto src_entry = SExtractV8(src_vec, i);
    auto mask = SShr(src_entry, decltype(src_entry)(7));
    auto abs_value = SSub(SXor(src_entry, mask), mask);
    dst_vec = SInsertV8(dst_vec, i, abs_value);
  }
  SWriteV8(dst, dst_vec);
  return memory;
}

template <typename D, typename S1>
DEF_SEM(PABSW, D dst, S1 src1) {
  auto src_vec = SReadV16(src1);
  auto dst_vec = SClearV16(SReadV16(dst));
  auto vec_count = NumVectorElems(src_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto src_entry = SExtractV16(src_vec, i);
    auto mask = SShr(src_entry, decltype(src_entry)(15));
    auto abs_value = SSub(SXor(src_entry, mask), mask);
    dst_vec = SInsertV16(dst_vec, i, abs_value);
  }
  SWriteV16(dst, dst_vec);
  return memory;
}

template <typename D, typename S1>
DEF_SEM(PABSD, D dst, S1 src1) {
  auto src_vec = SReadV32(src1);
  auto dst_vec = SClearV32(SReadV32(dst));
  auto vec_count = NumVectorElems(src_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto src_entry = SExtractV32(src_vec, i);
    auto mask = SShr(src_entry, decltype(src_entry)(31));
    auto abs_value = SSub(SXor(src_entry, mask), mask);
    dst_vec = SInsertV32(dst_vec, i, abs_value);
  }
  SWriteV32(dst, dst_vec);
  return memory;
}
}  // namespace

DEF_ISEL(PABSB_MMXq_MMXq) = PABSB<V64W, V64>;
DEF_ISEL(PABSB_MMXq_MEMq) = PABSB<V64W, MV64>;
DEF_ISEL(PABSB_XMMdq_XMMdq) = PABSB<V128W, V128>;
DEF_ISEL(PABSB_XMMdq_MEMdq) = PABSB<V128W, MV128>;

DEF_ISEL(PABSW_MMXq_MMXq) = PABSW<V64W, V64>;
DEF_ISEL(PABSW_MMXq_MEMq) = PABSW<V64W, MV64>;
DEF_ISEL(PABSW_XMMdq_XMMdq) = PABSW<V128W, V128>;
DEF_ISEL(PABSW_XMMdq_MEMdq) = PABSW<V128W, MV128>;

DEF_ISEL(PABSD_MMXq_MMXq) = PABSD<V64W, V64>;
DEF_ISEL(PABSD_MMXq_MEMq) = PABSD<V64W, MV64>;
DEF_ISEL(PABSD_XMMdq_XMMdq) = PABSD<V128W, V128>;
DEF_ISEL(PABSD_XMMdq_MEMdq) = PABSD<V128W, MV128>;

namespace {

// Need a better solution for handling PACKSS;
// Soln : Sign extension and compare
template <typename D, typename S1, typename S2>
DEF_SEM(PACKSSWB, D dst, S1 src1, S2 src2) {
  auto src1_vec = SReadV16(src1);
  auto src2_vec = SReadV16(src2);
  auto dst_vec = SClearV8(SReadV8(dst));

  // Convert signed word to saturated signed byte
  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto v1 = SExtractV16(src1_vec, i);
    auto v2 = SExtractV8(dst_vec, i);
    auto value =
        Select(SCmpGt(v1, SExt(Maximize(v2))), Maximize(v2), Trunc(v1));
    value = Select(SCmpLt(v1, SExt(Minimize(v2))), Minimize(v2), value);
    dst_vec = SInsertV8(dst_vec, i, value);
  }
  _Pragma("unroll") for (size_t i = 0; i < NumVectorElems(src2_vec); i++) {
    auto v1 = SExtractV16(src2_vec, i);
    auto v2 = SExtractV8(dst_vec, i);
    auto value =
        Select(SCmpGt(v1, SExt(Maximize(v2))), Maximize(v2), Trunc(v1));
    value = Select(SCmpLt(v1, SExt(Minimize(v2))), Minimize(v2), value);
    dst_vec = SInsertV8(dst_vec, i + vec_count, value);
  }
  SWriteV8(dst, dst_vec);
  return memory;
}
}  // namespace

DEF_ISEL(PACKSSWB_MMXq_MMXq) = PACKSSWB<V64W, V64, V64>;
DEF_ISEL(PACKSSWB_MMXq_MEMq) = PACKSSWB<V64W, V64, MV64>;
DEF_ISEL(PACKSSWB_XMMdq_XMMdq) = PACKSSWB<V128W, V128, V128>;
DEF_ISEL(PACKSSWB_XMMdq_MEMdq) = PACKSSWB<V128W, V128, MV128>;

namespace {
template <typename D, typename S1, typename S2>
DEF_SEM(PACKSSDW, D dst, S1 src1, S2 src2) {
  auto src1_vec = SReadV32(src1);
  auto src2_vec = SReadV32(src2);
  auto dst_vec = SClearV16(SReadV16(dst));

  // Convert signed word to saturated signed byte
  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto v1 = SExtractV32(src1_vec, i);
    auto v2 = SExtractV16(dst_vec, i);
    auto value =
        Select(SCmpGt(v1, SExt(Maximize(v2))), Maximize(v2), Trunc(v1));
    value = Select(SCmpLt(v1, SExt(Minimize(v2))), Minimize(v2), value);
    dst_vec = SInsertV16(dst_vec, i, value);
  }
  _Pragma("unroll") for (size_t i = 0; i < NumVectorElems(src2_vec); i++) {
    auto v1 = SExtractV32(src2_vec, i);
    auto v2 = SExtractV16(dst_vec, i);
    auto value =
        Select(SCmpGt(v1, SExt(Maximize(v2))), Maximize(v2), Trunc(v1));
    value = Select(SCmpLt(v1, SExt(Minimize(v2))), Minimize(v2), value);
    dst_vec = SInsertV16(dst_vec, i + vec_count, value);
  }
  SWriteV16(dst, dst_vec);
  return memory;
}
}  // namespace

DEF_ISEL(PACKSSDW_MMXq_MMXq) = PACKSSDW<V64W, V64, V64>;
DEF_ISEL(PACKSSDW_MMXq_MEMq) = PACKSSDW<V64W, V64, MV64>;
DEF_ISEL(PACKSSDW_XMMdq_XMMdq) = PACKSSDW<V128W, V128, V128>;
DEF_ISEL(PACKSSDW_XMMdq_MEMdq) = PACKSSDW<V128W, V128, MV128>;

namespace {
template <typename D, typename S1>
DEF_SEM(PEXTRB, D dst, S1 src1, I8 src2) {
  auto src1_vec = UReadV8(src1);
  auto count = Read(src2);
  auto vec_count = UInt8(NumVectorElems(src1_vec));
  auto sel_index = URem(count, vec_count);
  auto word = UExtractV8(src1_vec, sel_index);
  WriteZExt(dst, word);
  return memory;
}

template <typename D, typename S1>
DEF_SEM(PEXTRW, D dst, S1 src1, I8 src2) {
  auto src1_vec = UReadV16(src1);
  auto count = Read(src2);
  auto vec_count = UInt8(NumVectorElems(src1_vec));
  auto sel_index = URem(count, vec_count);
  auto word = UExtractV16(src1_vec, sel_index);
  WriteZExt(dst, word);
  return memory;
}

template <typename D, typename S1>
DEF_SEM(PEXTRD, D dst, S1 src1, I8 src2) {
  auto src1_vec = UReadV32(src1);
  auto count = Read(src2);
  auto vec_count = UInt8(NumVectorElems(src1_vec));
  auto sel_index = URem(count, vec_count);
  auto word = UExtractV32(src1_vec, sel_index);
  WriteZExt(dst, word);
  return memory;
}

#if 64 == ADDRESS_SIZE_BITS
template <typename D, typename S1>
DEF_SEM(PEXTRQ, D dst, S1 src1, I8 src2) {
  auto src1_vec = UReadV64(src1);
  auto count = Read(src2);
  auto vec_count = UInt8(NumVectorElems(src1_vec));
  auto sel_index = URem(count, vec_count);
  auto word = UExtractV64(src1_vec, sel_index);
  WriteZExt(dst, word);
  return memory;
}
#endif  // 64 == ADDRESS_SIZE_BITS

}  // namespace

DEF_ISEL(PEXTRB_MEMb_XMMdq_IMMb) = PEXTRB<M8W, V128>;
DEF_ISEL(PEXTRB_GPR32d_XMMdq_IMMb) = PEXTRB<R32W, V128>;
IF_AVX(DEF_ISEL(VPEXTRB_MEMb_XMMdq_IMMb) = PEXTRB<M8W, V128>;)
IF_AVX(DEF_ISEL(VPEXTRB_GPR32d_XMMdq_IMMb) = PEXTRB<R32W, V128>;)

DEF_ISEL(PEXTRW_GPR32_MMXq_IMMb) = PEXTRW<R32W, V64>;
DEF_ISEL(PEXTRW_GPR32_XMMdq_IMMb) = PEXTRW<R32W, V128>;
DEF_ISEL(PEXTRW_SSE4_MEMw_XMMdq_IMMb) = PEXTRW<M16W, V128>;
DEF_ISEL(PEXTRW_SSE4_GPR32_XMMdq_IMMb) = PEXTRW<R32W, V128>;
IF_AVX(DEF_ISEL(VPEXTRW_MEMw_XMMdq_IMMb) = PEXTRW<M16W, V128>;)
IF_AVX(DEF_ISEL(VPEXTRW_GPR32d_XMMdq_IMMb_15) = PEXTRW<R32W, V128>;)
IF_AVX(DEF_ISEL(VPEXTRW_GPR32d_XMMdq_IMMb_C5) = PEXTRW<R32W, V128>;)

DEF_ISEL(PEXTRD_MEMd_XMMdq_IMMb) = PEXTRD<M32W, V128>;
DEF_ISEL(PEXTRD_GPR32d_XMMdq_IMMb) = PEXTRD<R32W, V128>;
IF_AVX(DEF_ISEL(VPEXTRD_MEMd_XMMdq_IMMb) = PEXTRD<M32W, V128>;)
IF_AVX(DEF_ISEL(VPEXTRD_GPR32d_XMMdq_IMMb) = PEXTRD<R32W, V128>;)

IF_64BIT(DEF_ISEL(PEXTRQ_MEMq_XMMdq_IMMb) = PEXTRQ<M64W, V128>;)
IF_64BIT(DEF_ISEL(PEXTRQ_GPR64q_XMMdq_IMMb) = PEXTRQ<R64W, V128>;)
IF_64BIT(IF_AVX(DEF_ISEL(VPEXTRQ_MEMq_XMMdq_IMMb) = PEXTRQ<M64W, V128>;))
IF_64BIT(IF_AVX(DEF_ISEL(VPEXTRQ_GPR64q_XMMdq_IMMb) = PEXTRQ<R64W, V128>;))

/*

5314 VPEXTRB VPEXTRB_GPR32u8_XMMu8_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_128N ATTRIBUTES:
5315 VPEXTRB VPEXTRB_MEMu8_XMMu8_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_128N ATTRIBUTES: DISP8_GPR_WRITER_STORE_BYTE

5320 VPEXTRW VPEXTRW_GPR32u16_XMMu16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_128N ATTRIBUTES:
5321 VPEXTRW VPEXTRW_MEMu16_XMMu16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_128N ATTRIBUTES: DISP8_GPR_WRITER_STORE_WORD
5322 VPEXTRW VPEXTRW_GPR32u16_XMMu16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_128N ATTRIBUTES:

5316 VPEXTRD VPEXTRD_GPR32u32_XMMu32_IMM8_AVX512 AVX512 AVX512EVEX AVX512DQ_128N ATTRIBUTES:
5317 VPEXTRD VPEXTRD_MEMu32_XMMu32_IMM8_AVX512 AVX512 AVX512EVEX AVX512DQ_128N ATTRIBUTES: DISP8_GPR_WRITER_STORE

5318 VPEXTRQ VPEXTRQ_GPR64u64_XMMu64_IMM8_AVX512 AVX512 AVX512EVEX AVX512DQ_128N ATTRIBUTES:
5319 VPEXTRQ VPEXTRQ_MEMu64_XMMu64_IMM8_AVX512 AVX512 AVX512EVEX AVX512DQ_128N ATTRIBUTES: DISP8_GPR_WRITER_STORE
 */


namespace {
template <typename S2>
DEF_SEM(PALIGNR_64, V64W dst, V64 src1, S2 src2, I8 imm1) {
  auto src1_vec = UReadV64(src1);
  auto src2_vec = UReadV64(src2);
  auto shift = URem(static_cast<uint64_t>(UMul(Read(imm1), 0x8_u8)), 65_u64);
  auto dst_vec = UClearV64(UReadV64(dst));

  // Concat src and dst and right shift the bits
  auto src1_elem = UExtractV64(src1_vec, 0);
  auto src2_elem = UExtractV64(src2_vec, 0);
  auto zero_shift = UCmpEq(shift, 0_u64);
  auto max_shift = UCmpEq(shift, 64_u64);

  auto src1_elem_high =
      Select(zero_shift, 0_u64, UShl(src1_elem, USub(64_u64, shift)));

  auto src2_elem_low = Select(max_shift, src1_elem, UShr(src2_elem, shift));

  auto combined = UOr(src1_elem_high, src2_elem_low);
  UWriteV64(dst, UInsertV64(dst_vec, 0, combined));
  return memory;
}

template <typename S2>
DEF_SEM(PALIGNR_128, V128W dst, V128 src1, S2 src2, I8 imm1) {
  auto src1_vec = UReadV128(src1);
  auto src2_vec = UReadV128(src2);
  auto shift = URem(static_cast<uint128_t>(UMul(Read(imm1), 0x8_u8)), 129_u128);
  auto dst_vec = UClearV128(UReadV128(dst));

  // Concat src and dst and right shift the bits
  auto src1_elem = UExtractV128(src1_vec, 0);
  auto src2_elem = UExtractV128(src2_vec, 0);
  auto zero_shift = UCmpEq(shift, 0_u128);
  auto max_shift = UCmpEq(shift, 128_u128);

  auto src1_elem_high =
      Select(zero_shift, 0_u128, UShl(src1_elem, USub(128_u128, shift)));
  auto src2_elem_low = Select(max_shift, src1_elem, UShr(src2_elem, shift));

  auto combined = UOr(src1_elem_high, src2_elem_low);
  UWriteV128(dst, UInsertV128(dst_vec, 0, combined));
  return memory;
}

}  // namespace

DEF_ISEL(PALIGNR_MMXq_MMXq_IMMb) = PALIGNR_64<V64>;
DEF_ISEL(PALIGNR_MMXq_MEMq_IMMb) = PALIGNR_64<MV64>;
DEF_ISEL(PALIGNR_XMMdq_XMMdq_IMMb) = PALIGNR_128<V128>;
DEF_ISEL(PALIGNR_XMMdq_MEMdq_IMMb) = PALIGNR_128<MV128>;

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(PSRLW, D dst, S1 src1, S2 src2) {
  auto src1_vec = UReadV16(src1);
  auto count = Read(src2);
  auto dst_vec = UClearV16(UReadV16(dst));

  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto v1 = UExtractV16(src1_vec, i);
    auto temp = Select(UCmpGt(count, static_cast<decltype(count)>(15)),
                       static_cast<decltype(v1)>(0),
                       UShr(v1, static_cast<decltype(v1)>(count)));
    dst_vec = UInsertV16(dst_vec, i, temp);
  }
  UWriteV16(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PSRLW_V, D dst, S1 src1, S2 src2) {
  auto src1_vec = UReadV16(src1);
  auto src2_vec = UReadV64(src2);
  auto count = UExtractV64(src2_vec, 0);
  auto dst_vec = UClearV16(UReadV16(dst));

  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto v1 = UExtractV16(src1_vec, i);
    auto temp = Select(UCmpGt(count, static_cast<decltype(count)>(15)),
                       static_cast<decltype(v1)>(0),
                       UShr(v1, static_cast<decltype(v1)>(count)));
    dst_vec = UInsertV16(dst_vec, i, temp);
  }
  UWriteV16(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PSRLD, D dst, S1 src1, S2 src2) {
  auto src1_vec = UReadV32(src1);
  auto count = Read(src2);
  auto dst_vec = UClearV32(UReadV32(dst));

  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto v1 = UExtractV32(src1_vec, i);
    auto temp = Select(UCmpGt(count, static_cast<decltype(count)>(31)),
                       static_cast<decltype(v1)>(0),
                       UShr(v1, static_cast<decltype(v1)>(count)));
    dst_vec = UInsertV32(dst_vec, i, temp);
  }
  UWriteV32(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PSRLD_V, D dst, S1 src1, S2 src2) {
  auto src1_vec = UReadV32(src1);
  auto src2_vec = UReadV64(src2);
  auto count = UExtractV64(src2_vec, 0);
  auto dst_vec = UClearV32(UReadV32(dst));

  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto v1 = UExtractV32(src1_vec, i);
    auto temp = Select(UCmpGt(count, static_cast<decltype(count)>(31)),
                       static_cast<decltype(v1)>(0),
                       UShr(v1, static_cast<decltype(v1)>(count)));
    dst_vec = UInsertV32(dst_vec, i, temp);
  }
  UWriteV32(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PSRLQ, D dst, S1 src1, S2 src2) {
  auto src1_vec = UReadV64(src1);
  auto count = Read(src2);
  auto dst_vec = UClearV64(UReadV64(dst));

  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto v1 = UExtractV64(src1_vec, i);
    auto temp = Select(UCmpGt(count, static_cast<decltype(count)>(63)),
                       static_cast<decltype(v1)>(0),
                       UShr(v1, static_cast<decltype(v1)>(count)));
    dst_vec = UInsertV64(dst_vec, i, temp);
  }
  UWriteV64(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PSRLQ_V, D dst, S1 src1, S2 src2) {
  auto src1_vec = UReadV64(src1);
  auto src2_vec = UReadV64(src2);
  auto count = UExtractV64(src2_vec, 0);
  auto dst_vec = UClearV64(UReadV64(dst));

  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto v1 = UExtractV64(src1_vec, i);
    auto temp = Select(UCmpGt(count, static_cast<decltype(count)>(63)),
                       static_cast<decltype(v1)>(0),
                       UShr(v1, static_cast<decltype(v1)>(count)));
    dst_vec = UInsertV64(dst_vec, i, temp);
  }
  UWriteV64(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PSRAW, D dst, S1 src1, S2 src2) {
  auto src1_vec = SReadV16(src1);
  auto count = Read(src2);
  auto dst_vec = SClearV16(SReadV16(dst));

  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto v1 = SExtractV16(src1_vec, i);
    count = Select(UCmpGt(count, static_cast<decltype(count)>(15)),
                   static_cast<decltype(count)>(16), count);
    dst_vec =
        SInsertV16(dst_vec, i, SShr(v1, static_cast<decltype(v1)>(count)));
  }
  SWriteV16(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PSRAW_V, D dst, S1 src1, S2 src2) {
  auto src1_vec = SReadV16(src1);
  auto src2_vec = UReadV64(src2);
  auto count = UExtractV64(src2_vec, 0);
  auto dst_vec = SClearV16(SReadV16(dst));

  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto v1 = SExtractV16(src1_vec, i);
    count = Select(UCmpGt(count, static_cast<decltype(count)>(15)),
                   static_cast<decltype(count)>(16), count);
    dst_vec =
        SInsertV16(dst_vec, i, SShr(v1, static_cast<decltype(v1)>(count)));
  }
  SWriteV16(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PSRAD, D dst, S1 src1, S2 src2) {
  auto src1_vec = SReadV32(src1);
  auto count = Read(src2);
  auto dst_vec = SClearV32(SReadV32(dst));

  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto v1 = SExtractV32(src1_vec, i);
    count = Select(UCmpGt(count, static_cast<decltype(count)>(31)),
                   static_cast<decltype(count)>(32), count);
    dst_vec =
        SInsertV32(dst_vec, i, SShr(v1, static_cast<decltype(v1)>(count)));
  }
  SWriteV32(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PSRAD_V, D dst, S1 src1, S2 src2) {
  auto src1_vec = SReadV32(src1);
  auto src2_vec = UReadV64(src2);
  auto count = UExtractV64(src2_vec, 0);
  auto dst_vec = SClearV32(SReadV32(dst));

  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto v1 = SExtractV32(src1_vec, i);
    count = Select(UCmpGt(count, static_cast<decltype(count)>(31)),
                   static_cast<decltype(count)>(32), count);
    dst_vec =
        SInsertV32(dst_vec, i, SShr(v1, static_cast<decltype(v1)>(count)));
  }
  SWriteV32(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(PSRLW_MMXq_IMMb) = PSRLW<V64W, V64, I8>;
DEF_ISEL(PSRLW_MMXq_MMXq) = PSRLW<V64W, V64, R64>;
DEF_ISEL(PSRLW_MMXq_MEMq) = PSRLW<V64W, V64, M64>;
DEF_ISEL(PSRLW_XMMdq_IMMb) = PSRLW<V128W, V128, I8>;
DEF_ISEL(PSRLW_XMMdq_XMMdq) = PSRLW_V<V128W, V128, V128>;
DEF_ISEL(PSRLW_XMMdq_MEMdq) = PSRLW_V<V128W, V128, MV128>;

DEF_ISEL(PSRLD_MMXq_IMMb) = PSRLD<V64W, V64, I8>;
DEF_ISEL(PSRLD_MMXq_MMXq) = PSRLD<V64W, V64, R64>;
DEF_ISEL(PSRLD_MMXq_MEMq) = PSRLD<V64W, V64, M64>;
DEF_ISEL(PSRLD_XMMdq_IMMb) = PSRLD<V128W, V128, I8>;
DEF_ISEL(PSRLD_XMMdq_XMMdq) = PSRLD_V<V128W, V128, V128>;
DEF_ISEL(PSRLD_XMMdq_MEMdq) = PSRLD_V<V128W, V128, MV128>;

DEF_ISEL(PSRLQ_MMXq_IMMb) = PSRLQ<V64W, V64, I8>;
DEF_ISEL(PSRLQ_MMXq_MMXq) = PSRLQ<V64W, V64, R64>;
DEF_ISEL(PSRLQ_MMXq_MEMq) = PSRLQ<V64W, V64, M64>;
DEF_ISEL(PSRLQ_XMMdq_IMMb) = PSRLQ<V128W, V128, I8>;
DEF_ISEL(PSRLQ_XMMdq_XMMdq) = PSRLQ_V<V128W, V128, V128>;
DEF_ISEL(PSRLQ_XMMdq_MEMdq) = PSRLQ_V<V128W, V128, MV128>;
IF_AVX(DEF_ISEL(VPSRLQ_XMMdq_XMMdq_MEMdq) = PSRLQ_V<VV128W, V128, MV128>;)
IF_AVX(DEF_ISEL(VPSRLQ_XMMdq_XMMdq_XMMdq) = PSRLQ_V<VV128W, V128, V128>;)
IF_AVX(DEF_ISEL(VPSRLQ_XMMdq_XMMdq_IMMb) = PSRLQ<VV128W, V128, I8>;)
IF_AVX(DEF_ISEL(VPSRLQ_YMMqq_YMMqq_IMMb) = PSRLQ<VV256W, V256, I8>;)
IF_AVX(DEF_ISEL(VPSRLQ_YMMqq_YMMqq_XMMq) = PSRLQ_V<VV256W, V256, V128>;)
IF_AVX(DEF_ISEL(VPSRLQ_YMMqq_YMMqq_MEMdq) = PSRLQ_V<VV256W, V256, MV128>;)

/*
5620 VPSRLQ VPSRLQ_ZMMu64_MASKmskw_ZMMu64_XMMu64_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
5621 VPSRLQ VPSRLQ_ZMMu64_MASKmskw_ZMMu64_MEMu64_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: DISP8_MEM128 MASKOP_EVEX
5622 VPSRLQ VPSRLQ_ZMMu64_MASKmskw_ZMMu64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
5623 VPSRLQ VPSRLQ_ZMMu64_MASKmskw_MEMu64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5624 VPSRLQ VPSRLQ_XMMu64_MASKmskw_XMMu64_XMMu64_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
5625 VPSRLQ VPSRLQ_XMMu64_MASKmskw_XMMu64_MEMu64_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: DISP8_MEM128 MASKOP_EVEX
5626 VPSRLQ VPSRLQ_XMMu64_MASKmskw_XMMu64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
5627 VPSRLQ VPSRLQ_XMMu64_MASKmskw_MEMu64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
5628 VPSRLQ VPSRLQ_YMMu64_MASKmskw_YMMu64_XMMu64_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
5629 VPSRLQ VPSRLQ_YMMu64_MASKmskw_YMMu64_MEMu64_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: DISP8_MEM128 MASKOP_EVEX
5630 VPSRLQ VPSRLQ_YMMu64_MASKmskw_YMMu64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
5631 VPSRLQ VPSRLQ_YMMu64_MASKmskw_MEMu64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
*/

DEF_ISEL(PSRAW_MMXq_IMMb) = PSRAW<V64W, V64, I8>;
DEF_ISEL(PSRAW_MMXq_MMXq) = PSRAW<V64W, V64, R64>;
DEF_ISEL(PSRAW_MMXq_MEMq) = PSRAW<V64W, V64, M64>;
DEF_ISEL(PSRAW_XMMdq_IMMb) = PSRAW<V128W, V128, I8>;
DEF_ISEL(PSRAW_XMMdq_XMMdq) = PSRAW_V<V128W, V128, V128>;
DEF_ISEL(PSRAW_XMMdq_MEMdq) = PSRAW_V<V128W, V128, MV128>;

DEF_ISEL(PSRAD_MMXq_IMMb) = PSRAD<V64W, V64, I8>;
DEF_ISEL(PSRAD_MMXq_MMXq) = PSRAD<V64W, V64, R64>;
DEF_ISEL(PSRAD_MMXq_MEMq) = PSRAD<V64W, V64, M64>;
DEF_ISEL(PSRAD_XMMdq_IMMb) = PSRAD<V128W, V128, I8>;
DEF_ISEL(PSRAD_XMMdq_XMMdq) = PSRAD_V<V128W, V128, V128>;
DEF_ISEL(PSRAD_XMMdq_MEMdq) = PSRAD_V<V128W, V128, MV128>;

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(PSLLW, D dst, S1 src1, S2 src2) {
  auto src1_vec = SReadV16(src1);
  auto count = Read(src2);
  auto dst_vec = SClearV16(SReadV16(dst));

  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto v1 = SExtractV16(src1_vec, i);
    auto temp = Select(UCmpGt(count, static_cast<decltype(count)>(15)), 0_s16,
                       SShl(v1, static_cast<int16_t>(count)));
    dst_vec = SInsertV16(dst_vec, i, temp);
  }
  SWriteV16(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PSLLW_V, D dst, S1 src1, S2 src2) {
  auto src1_vec = SReadV16(src1);
  auto src2_vec = UReadV64(src2);
  auto count = UExtractV64(src2_vec, 0);
  auto dst_vec = SClearV16(SReadV16(dst));

  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto v1 = SExtractV16(src1_vec, i);
    auto temp = Select(UCmpGt(count, 15_u64), 0_s16,
                       SShl(v1, static_cast<int16_t>(count)));
    dst_vec = SInsertV16(dst_vec, i, temp);
  }
  SWriteV16(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PSLLD, D dst, S1 src1, S2 src2) {
  auto src1_vec = SReadV32(src1);
  auto count = Read(src2);
  auto dst_vec = SClearV32(SReadV32(dst));

  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto v1 = SExtractV32(src1_vec, i);
    auto temp = Select(UCmpGt(count, static_cast<decltype(count)>(31)), 0_s32,
                       SShl(v1, static_cast<int32_t>(count)));
    dst_vec = SInsertV32(dst_vec, i, temp);
  }
  SWriteV32(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PSLLD_V, D dst, S1 src1, S2 src2) {
  auto src1_vec = SReadV32(src1);
  auto src2_vec = UReadV64(src2);
  auto count = UExtractV64(src2_vec, 0);
  auto dst_vec = SClearV32(SReadV32(dst));

  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto v1 = SExtractV32(src1_vec, i);
    auto temp = Select(UCmpGt(count, 31_u64), 0_s32,
                       SShl(v1, static_cast<int32_t>(count)));
    dst_vec = SInsertV32(dst_vec, i, temp);
  }
  SWriteV32(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PSLLQ, D dst, S1 src1, S2 src2) {
  auto src1_vec = SReadV64(src1);
  auto count = Read(src2);
  auto dst_vec = SClearV64(SReadV64(dst));

  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto v1 = SExtractV64(src1_vec, i);
    auto temp = Select(UCmpGt(count, static_cast<decltype(count)>(63)), 0_s64,
                       SShl(v1, static_cast<int64_t>(count)));
    dst_vec = SInsertV64(dst_vec, i, temp);
  }
  SWriteV64(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PSLLQ_V, D dst, S1 src1, S2 src2) {
  auto src1_vec = SReadV64(src1);
  auto src2_vec = UReadV64(src2);
  auto count = UExtractV64(src2_vec, 0);
  auto dst_vec = SClearV64(SReadV64(dst));

  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto v1 = SExtractV64(src1_vec, i);
    auto temp = Select(UCmpGt(count, 63_u64), 0_s64,
                       SShl(v1, static_cast<int64_t>(count)));
    dst_vec = SInsertV64(dst_vec, i, temp);
  }
  SWriteV64(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(PSLLW_MMXq_IMMb) = PSLLW<V64W, V64, I8>;
DEF_ISEL(PSLLW_MMXq_MMXq) = PSLLW<V64W, V64, R64>;
DEF_ISEL(PSLLW_MMXq_MEMq) = PSLLW<V64W, V64, M64>;
DEF_ISEL(PSLLW_XMMdq_IMMb) = PSLLW<V128W, V128, I8>;
DEF_ISEL(PSLLW_XMMdq_XMMdq) = PSLLW_V<V128W, V128, V128>;
DEF_ISEL(PSLLW_XMMdq_MEMdq) = PSLLW_V<V128W, V128, MV128>;

DEF_ISEL(PSLLD_MMXq_IMMb) = PSLLD<V64W, V64, I8>;
DEF_ISEL(PSLLD_MMXq_MMXq) = PSLLD<V64W, V64, R64>;
DEF_ISEL(PSLLD_MMXq_MEMq) = PSLLD<V64W, V64, M64>;
DEF_ISEL(PSLLD_XMMdq_IMMb) = PSLLD<V128W, V128, I8>;
DEF_ISEL(PSLLD_XMMdq_XMMdq) = PSLLD_V<V128W, V128, V128>;
DEF_ISEL(PSLLD_XMMdq_MEMdq) = PSLLD_V<V128W, V128, MV128>;

DEF_ISEL(PSLLQ_MMXq_IMMb) = PSLLQ<V64W, V64, I8>;
DEF_ISEL(PSLLQ_MMXq_MMXq) = PSLLQ<V64W, V64, R64>;
DEF_ISEL(PSLLQ_MMXq_MEMq) = PSLLQ<V64W, V64, M64>;
DEF_ISEL(PSLLQ_XMMdq_IMMb) = PSLLQ<V128W, V128, I8>;
DEF_ISEL(PSLLQ_XMMdq_XMMdq) = PSLLQ_V<V128W, V128, V128>;
DEF_ISEL(PSLLQ_XMMdq_MEMdq) = PSLLQ_V<V128W, V128, MV128>;
IF_AVX(DEF_ISEL(VPSLLQ_XMMdq_XMMdq_IMMb) = PSLLQ<VV128W, V128, I8>;)
IF_AVX(DEF_ISEL(VPSLLQ_XMMdq_XMMdq_XMMdq) = PSLLQ_V<VV128W, V128, V128>;)
IF_AVX(DEF_ISEL(VPSLLQ_XMMdq_XMMdq_MEMdq) = PSLLQ_V<VV128W, V128, MV128>;)
IF_AVX(DEF_ISEL(VPSLLQ_YMMqq_YMMqq_IMMb) = PSLLQ<VV256W, V256, I8>;)
IF_AVX(DEF_ISEL(VPSLLQ_YMMqq_YMMqq_XMMq) = PSLLQ_V<VV256W, V256, V128>;)
IF_AVX(DEF_ISEL(VPSLLQ_YMMqq_YMMqq_MEMdq) = PSLLQ_V<VV256W, V256, MV128>;)

/*
4451 VPSLLQ VPSLLQ_ZMMu64_MASKmskw_ZMMu64_XMMu64_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
4452 VPSLLQ VPSLLQ_ZMMu64_MASKmskw_ZMMu64_MEMu64_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: DISP8_MEM128 MASKOP_EVEX
4453 VPSLLQ VPSLLQ_ZMMu64_MASKmskw_ZMMu64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: MASKOP_EVEX
4454 VPSLLQ VPSLLQ_ZMMu64_MASKmskw_MEMu64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_512 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
4455 VPSLLQ VPSLLQ_XMMu64_MASKmskw_XMMu64_XMMu64_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
4456 VPSLLQ VPSLLQ_XMMu64_MASKmskw_XMMu64_MEMu64_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: DISP8_MEM128 MASKOP_EVEX
4457 VPSLLQ VPSLLQ_XMMu64_MASKmskw_XMMu64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: MASKOP_EVEX
4458 VPSLLQ VPSLLQ_XMMu64_MASKmskw_MEMu64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_128 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
4459 VPSLLQ VPSLLQ_YMMu64_MASKmskw_YMMu64_XMMu64_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
4460 VPSLLQ VPSLLQ_YMMu64_MASKmskw_YMMu64_MEMu64_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: DISP8_MEM128 MASKOP_EVEX
4461 VPSLLQ VPSLLQ_YMMu64_MASKmskw_YMMu64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: MASKOP_EVEX
4462 VPSLLQ VPSLLQ_YMMu64_MASKmskw_MEMu64_IMM8_AVX512 AVX512 AVX512EVEX AVX512F_256 ATTRIBUTES: BROADCAST_ENABLED DISP8_FULL MASKOP_EVEX MEMORY_FAULT_SUPPRESSION
*/

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(PSIGNB, D dst, S1 src1, S2 src2) {
  auto src1_vec = SReadV8(src1);
  auto src2_vec = SReadV8(src2);
  auto dst_vec = SClearV8(SReadV8(dst));

  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto v1 = SExtractV8(src1_vec, i);
    auto v2 = SExtractV8(src2_vec, i);
    auto is_neg = SignFlag(v2);
    auto is_zero = ZeroFlag(v2);
    auto value = Select(is_zero, 0_s8, Select(is_neg, SNeg(v1), v1));
    dst_vec = SInsertV8(dst_vec, i, value);
  }
  SWriteV8(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PSIGNW, D dst, S1 src1, S2 src2) {
  auto src1_vec = SReadV16(src1);
  auto src2_vec = SReadV16(src2);
  auto dst_vec = SClearV16(SReadV16(dst));

  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto v1 = SExtractV16(src1_vec, i);
    auto v2 = SExtractV16(src2_vec, i);
    auto is_neg = SignFlag(v2);
    auto is_zero = ZeroFlag(v2);
    auto value = Select(is_zero, 0_s16, Select(is_neg, SNeg(v1), v1));
    dst_vec = SInsertV16(dst_vec, i, value);
  }
  SWriteV16(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PSIGND, D dst, S1 src1, S2 src2) {
  auto src1_vec = SReadV32(src1);
  auto src2_vec = SReadV32(src2);
  auto dst_vec = SClearV32(SReadV32(dst));

  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto v1 = SExtractV32(src1_vec, i);
    auto v2 = SExtractV32(src2_vec, i);
    auto is_neg = SignFlag(v2);
    auto is_zero = ZeroFlag(v2);
    auto value = Select(is_zero, 0_s32, Select(is_neg, SNeg(v1), v1));
    dst_vec = SInsertV32(dst_vec, i, value);
  }
  SWriteV32(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(PSIGNB_MMXq_MMXq) = PSIGNB<V64W, V64, V64>;
DEF_ISEL(PSIGNB_MMXq_MEMq) = PSIGNB<V64W, V64, MV64>;
DEF_ISEL(PSIGNB_XMMdq_XMMdq) = PSIGNB<V128W, V128, V128>;
DEF_ISEL(PSIGNB_XMMdq_MEMdq) = PSIGNB<V128W, V128, MV128>;

DEF_ISEL(PSIGNW_MMXq_MMXq) = PSIGNW<V64W, V64, V64>;
DEF_ISEL(PSIGNW_MMXq_MEMq) = PSIGNW<V64W, V64, MV64>;
DEF_ISEL(PSIGNW_XMMdq_XMMdq) = PSIGNW<V128W, V128, V128>;
DEF_ISEL(PSIGNW_XMMdq_MEMdq) = PSIGNW<V128W, V128, MV128>;

DEF_ISEL(PSIGND_MMXq_MMXq) = PSIGND<V64W, V64, V64>;
DEF_ISEL(PSIGND_MMXq_MEMq) = PSIGND<V64W, V64, MV64>;
DEF_ISEL(PSIGND_XMMdq_XMMdq) = PSIGND<V128W, V128, V128>;
DEF_ISEL(PSIGND_XMMdq_MEMdq) = PSIGND<V128W, V128, MV128>;

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(PSHUFB, D dst, S1 src1, S2 src2) {
  auto src1_vec = UReadV8(src1);
  auto src2_vec = UReadV8(src2);
  auto dst_vec = UClearV8(UReadV8(dst));

  auto vec_count = NumVectorElems(src1_vec);
  uint8_t mask = static_cast<uint8_t>(vec_count - 1u);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    uint8_t v1 = UExtractV8(src2_vec, i);
    uint8_t index = UAnd(v1, mask);
    uint8_t v2 = UExtractV8(src1_vec, index);
    uint8_t value = Select(SignFlag(v1), 0_u8, v2);
    dst_vec = UInsertV8(dst_vec, i, value);
  }
  UWriteV8(dst, dst_vec);
  return memory;
}

template <typename D, typename S1>
DEF_SEM(PSHUFW, D dst, S1 src1, I8 src2) {
  auto src_vec = UReadV16(src1);
  auto dst_vec = UClearV16(UReadV16(dst));
  auto order = Read(src2);

  auto vec_count = NumVectorElems(dst_vec);
  _Pragma("unroll") for (uint8_t i = 0; i < vec_count; i++) {
    auto mask = UAnd(UShr(order, i), 3_u8);
    auto v1 = UExtractV16(src_vec, mask);
    dst_vec = UInsertV16(dst_vec, i, v1);
  }
  UWriteV16(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(PSHUFB_MMXq_MMXq) = PSHUFB<V64W, V64, V64>;
DEF_ISEL(PSHUFB_MMXq_MEMq) = PSHUFB<V64W, V64, MV64>;
DEF_ISEL(PSHUFB_XMMdq_XMMdq) = PSHUFB<V128W, V128, V128>;
DEF_ISEL(PSHUFB_XMMdq_MEMdq) = PSHUFB<V128W, V128, MV128>;

DEF_ISEL(PSHUFW_MMXq_MMXq_IMMb) = PSHUFW<V64W, V64>;
DEF_ISEL(PSHUFW_MMXq_MEMq_IMMb) = PSHUFW<V64W, MV64>;

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(PSADBW, D dst, S1 src1, S2 src2) {
  auto src1_vec = UReadV8(src1);
  auto src2_vec = UReadV8(src2);
  auto dst_vec = UClearV64(UReadV64(dst));
  auto vec_count = NumVectorElems(dst_vec);

  _Pragma("unroll") for (size_t i = 0, k = 0; i < vec_count; i++) {
    uint16_t sum = 0;
    _Pragma("unroll") for (size_t j = 0; j < 8UL; ++j, ++k) {
      uint8_t v1 = UExtractV8(src1_vec, k);
      uint8_t v2 = UExtractV8(src2_vec, k);
      uint8_t abs_diff = Select(UCmpGte(v1, v2), USub(v1, v2), USub(v2, v1));
      sum = UAdd(sum, ZExt(abs_diff));
    }
    dst_vec = UInsertV64(dst_vec, i, UInt64(sum));
  }
  UWriteV64(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(PSADBW_MMXq_MMXq) = PSADBW<V64W, V64, V64>;
DEF_ISEL(PSADBW_MMXq_MEMq) = PSADBW<V64W, V64, MV64>;
DEF_ISEL(PSADBW_XMMdq_XMMdq) = PSADBW<V128W, V128, V128>;
DEF_ISEL(PSADBW_XMMdq_MEMdq) = PSADBW<V128W, V128, MV128>;

IF_AVX(DEF_ISEL(VPSADBW_XMMdq_XMMdq_MEMdq) = PSADBW<V128W, V128, MV128>;)
IF_AVX(DEF_ISEL(VPSADBW_XMMdq_XMMdq_XMMdq) = PSADBW<V128W, V128, V128>;)
IF_AVX(DEF_ISEL(VPSADBW_YMMqq_YMMqq_MEMqq) = PSADBW<VV256W, V256, MV256>;)
IF_AVX(DEF_ISEL(VPSADBW_YMMqq_YMMqq_YMMqq) = PSADBW<VV256W, V256, V256>;)

namespace {
template <typename D, typename S1, typename S2>
DEF_SEM(PMULUDQ, D dst, S1 src1, S2 src2) {
  auto src1_vec = UReadV32(src1);
  auto src2_vec = UReadV32(src2);
  auto dst_vec = UClearV64(UReadV64(dst));

  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count / 2; i++) {
    auto v1 = ZExt(UExtractV32(src1_vec, i * 2));
    auto v2 = ZExt(UExtractV32(src2_vec, i * 2));
    auto mul = UMul(v1, v2);
    dst_vec = UInsertV64(dst_vec, i, mul);
  }
  UWriteV64(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PMULLW, D dst, S1 src1, S2 src2) {
  auto src1_vec = SReadV16(src1);
  auto src2_vec = SReadV16(src2);
  auto dst_vec = SClearV16(SReadV16(dst));

  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto v1 = SExtractV16(src1_vec, i);
    auto v2 = SExtractV16(src2_vec, i);
    auto mul = SMul(SExt(v1), SExt(v2));
    dst_vec = SInsertV16(dst_vec, i, Trunc(mul));
  }
  SWriteV16(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PMULHW, D dst, S1 src1, S2 src2) {
  auto src1_vec = SReadV16(src1);
  auto src2_vec = SReadV16(src2);
  auto dst_vec = SClearV16(SReadV16(dst));

  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto v1 = SExtractV16(src1_vec, i);
    auto v2 = SExtractV16(src2_vec, i);
    auto mul = SMul(SExt(v1), SExt(v2));
    dst_vec = SInsertV16(dst_vec, i, Trunc(SShr(mul, 16_s32)));
  }
  SWriteV16(dst, dst_vec);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PMULHUW, D dst, S1 src1, S2 src2) {
  auto src1_vec = UReadV16(src1);
  auto src2_vec = UReadV16(src2);
  auto dst_vec = UClearV16(UReadV16(dst));

  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    auto v1 = UExtractV16(src1_vec, i);
    auto v2 = UExtractV16(src2_vec, i);
    auto mul = UMul(ZExt(v1), ZExt(v2));
    dst_vec = UInsertV16(dst_vec, i, Trunc(UShr(mul, 16_u32)));
  }
  UWriteV16(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(PMULUDQ_MMXq_MMXq) = PMULUDQ<V64W, V64, V64>;
DEF_ISEL(PMULUDQ_MMXq_MEMq) = PMULUDQ<V64W, V64, MV64>;
DEF_ISEL(PMULUDQ_XMMdq_XMMdq) = PMULUDQ<V128W, V128, V128>;
DEF_ISEL(PMULUDQ_XMMdq_MEMdq) = PMULUDQ<V128W, V128, MV128>;

DEF_ISEL(PMULLW_MMXq_MMXq) = PMULLW<V64W, V64, V64>;
DEF_ISEL(PMULLW_MMXq_MEMq) = PMULLW<V64W, V64, MV64>;
DEF_ISEL(PMULLW_XMMdq_XMMdq) = PMULLW<V128W, V128, V128>;
DEF_ISEL(PMULLW_XMMdq_MEMdq) = PMULLW<V128W, V128, MV128>;

DEF_ISEL(PMULHW_MMXq_MMXq) = PMULHW<V64W, V64, V64>;
DEF_ISEL(PMULHW_MMXq_MEMq) = PMULHW<V64W, V64, MV64>;
DEF_ISEL(PMULHW_XMMdq_XMMdq) = PMULHW<V128W, V128, V128>;
DEF_ISEL(PMULHW_XMMdq_MEMdq) = PMULHW<V128W, V128, MV128>;

DEF_ISEL(PMULHUW_MMXq_MMXq) = PMULHUW<V64W, V64, V64>;
DEF_ISEL(PMULHUW_MMXq_MEMq) = PMULHUW<V64W, V64, MV64>;
DEF_ISEL(PMULHUW_XMMdq_XMMdq) = PMULHUW<V128W, V128, V128>;
DEF_ISEL(PMULHUW_XMMdq_MEMdq) = PMULHUW<V128W, V128, MV128>;

namespace {

template <typename D, typename S>
DEF_SEM(PMOVMSKB, D dst, S src2) {
  auto src_vec = UReadV8(src2);
  uint32_t r32 = 0U;

  // reset all bits to zero
  auto vec_count = NumVectorElems(src_vec);
  _Pragma("unroll") for (size_t i = vec_count; i-- > 0;) {
    auto v1 = UExtractV8(src_vec, i);
    r32 = UOr(UShl(r32, 1_u32), static_cast<uint32_t>(UShr(v1, 7_u8)));
  }
  WriteZExt(dst, r32);
  return memory;
}

}  // namespace

DEF_ISEL(PMOVMSKB_GPR32_MMXq) = PMOVMSKB<R32W, V64>;
DEF_ISEL(PMOVMSKB_GPR32_XMMdq) = PMOVMSKB<R32W, V128>;
DEF_ISEL(VPMOVMSKB_GPR32d_XMMdq) = PMOVMSKB<R32W, V128>;
IF_AVX(DEF_ISEL(VPMOVMSKB_GPR32d_YMMqq) = PMOVMSKB<R32W, V256>;)

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(PINSRW, D dst, S1 src1, S2 src2, I8 src3) {
  auto dst_vec = UReadV16(src1);
  auto value = UInt16(Read(src2));
  auto index = URem(Read(src3), UInt8(NumVectorElems(dst_vec)));
  UWriteV16(dst, UInsertV16(dst_vec, index, value));
  return memory;
}

DEF_SEM(DoMOVNTQ_MEMq_MMXq, MV64W dst, V64 src1) {
  UWriteV64(dst, UReadV64(src1));
  return memory;
}

DEF_SEM(DoMASKMOVQ_MMXq_MMXq, V64 src1, V64 src2) {
  auto dst = VWritePtr<vec64_t>(Read(REG_XDI));
  auto dst_vec = UReadV8(dst);
  auto src1_vec = UReadV8(src1);
  auto src2_vec = UReadV8(src2);
  auto vec_count = NumVectorElems(src1_vec);
  _Pragma("unroll") for (size_t i = 0; i < vec_count; i++) {
    uint8_t src_byte = UExtractV8(src1_vec, i);
    uint8_t mask_byte = UExtractV8(src2_vec, i);
    uint8_t mem_byte = UExtractV8(dst_vec, i);
    uint8_t new_byte = Select(SignFlag(mask_byte), src_byte, mem_byte);
    dst_vec = UInsertV8(dst_vec, i, new_byte);
  }
  UWriteV8(dst, dst_vec);
  return memory;
}

DEF_SEM(DoEMMS) {
  state.mmx.elems[0].val.qwords.elems[0] = __remill_undefined_64();
  state.mmx.elems[1].val.qwords.elems[0] = __remill_undefined_64();
  state.mmx.elems[2].val.qwords.elems[0] = __remill_undefined_64();
  state.mmx.elems[3].val.qwords.elems[0] = __remill_undefined_64();
  state.mmx.elems[4].val.qwords.elems[0] = __remill_undefined_64();
  state.mmx.elems[5].val.qwords.elems[0] = __remill_undefined_64();
  state.mmx.elems[6].val.qwords.elems[0] = __remill_undefined_64();
  state.mmx.elems[7].val.qwords.elems[0] = __remill_undefined_64();

  state.st.elems[0].val = __remill_undefined_f64();
  state.st.elems[1].val = __remill_undefined_f64();
  state.st.elems[2].val = __remill_undefined_f64();
  state.st.elems[3].val = __remill_undefined_f64();
  state.st.elems[4].val = __remill_undefined_f64();
  state.st.elems[5].val = __remill_undefined_f64();
  state.st.elems[6].val = __remill_undefined_f64();
  state.st.elems[7].val = __remill_undefined_f64();

  // TODO(pag): Add FPU tag word stuff to the `State` structure, and reset
  //            it here.
  return memory;
}
}  // namespace

DEF_ISEL(PINSRW_MMXq_MEMw_IMMb) = PINSRW<V64W, V64, M16>;
DEF_ISEL(PINSRW_MMXq_GPR32_IMMb) = PINSRW<V64W, V64, R32>;
DEF_ISEL(PINSRW_XMMdq_MEMw_IMMb) = PINSRW<V128W, V128, M16>;
DEF_ISEL(PINSRW_XMMdq_GPR32_IMMb) = PINSRW<V128W, V128, R32>;
IF_AVX(DEF_ISEL(VPINSRW_XMMdq_XMMdq_MEMw_IMMb) = PINSRW<VV128W, V128, M16>);
IF_AVX(DEF_ISEL(VPINSRW_XMMdq_XMMdq_GPR32d_IMMb) = PINSRW<VV128W, V128, R32>);

namespace {

template <typename D, typename S1, typename S2>
DEF_SEM(PFMUL, D dst, S1 src_dst, S2 src) {
  auto src1 = FReadV32(src_dst);
  auto src2 = FReadV32(src);
  FWriteV32(dst, FMulV32(src1, src2));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PFADD, D dst, S1 src_dst, S2 src) {
  auto src1 = FReadV32(src_dst);
  auto src2 = FReadV32(src);
  FWriteV32(dst, FAddV32(src1, src2));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PFSUB, D dst, S1 src_dst, S2 src) {
  auto src1 = FReadV32(src_dst);
  auto src2 = FReadV32(src);
  FWriteV32(dst, FSubV32(src1, src2));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PFSUBR, D dst, S1 src_dst, S2 src) {
  auto src1 = FReadV32(src);
  auto src2 = FReadV32(src_dst);
  FWriteV32(dst, FSubV32(src1, src2));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PFMAX, D dst, S1 src_dst, S2 src) {
  auto src1 = FReadV32(src_dst);
  auto src2 = FReadV32(src);
  auto out = src1;
  _Pragma("unroll") for (auto i = 0u; i < 2; ++i) {
    auto s1_val = FExtractV32(src1, i);
    auto s2_val = FExtractV32(src2, i);
    if (!std::isunordered(s1_val, s2_val) && s2_val > s1_val) {
      out = FInsertV32(out, i, s2_val);
    }
  }
  FWriteV32(dst, out);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PFMIN, D dst, S1 src_dst, S2 src) {
  auto src1 = FReadV32(src_dst);
  auto src2 = FReadV32(src);
  auto out = src1;
  _Pragma("unroll") for (auto i = 0u; i < 2; ++i) {
    auto s1_val = FExtractV32(src1, i);
    auto s2_val = FExtractV32(src2, i);
    if (!std::isunordered(s1_val, s2_val) && s2_val < s1_val) {
      out = FInsertV32(out, i, s2_val);
    }
  }
  FWriteV32(dst, out);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PFCMPGT, D dst, S1 src_dst, S2 src) {
  auto src1 = FReadV32(src_dst);
  auto src2 = FReadV32(src);
  uint32v2_t out = {};
  _Pragma("unroll") for (auto i = 0u; i < 2; ++i) {
    auto s1_val = FExtractV32(src1, i);
    auto s2_val = FExtractV32(src2, i);
    if (!std::isunordered(s1_val, s2_val) && s1_val > s2_val) {
      out.elems[i] = ~0u;
    }
  }
  UWriteV32(dst, out);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PFCMPGE, D dst, S1 src_dst, S2 src) {
  auto src1 = FReadV32(src_dst);
  auto src2 = FReadV32(src);
  uint32v2_t out = {};
  _Pragma("unroll") for (auto i = 0u; i < 2; ++i) {
    auto s1_val = FExtractV32(src1, i);
    auto s2_val = FExtractV32(src2, i);
    if (!std::isunordered(s1_val, s2_val) && s1_val >= s2_val) {
      out.elems[i] = ~0u;
    }
  }
  UWriteV32(dst, out);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PFCMPEQ, D dst, S1 src_dst, S2 src) {
  auto src1 = FReadV32(src_dst);
  auto src2 = FReadV32(src);
  uint32v2_t out = {};
  _Pragma("unroll") for (auto i = 0u; i < 2; ++i) {
    auto s1_val = FExtractV32(src1, i);
    auto s2_val = FExtractV32(src2, i);
    if (!std::isunordered(s1_val, s2_val) && s1_val == s2_val) {
      out.elems[i] = ~0u;
    }
  }
  UWriteV32(dst, out);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PFRSQRT, D dst, S1, S2 src) {
  auto src2 = FReadV32(src);
  auto out = FClearV32(FReadV32(dst));
  out = FInsertV32(
      out, 0, FDiv(1.0f, SquareRoot32(memory, state, FExtractV32(src2, 0))));
  out = FInsertV32(
      out, 1, FDiv(1.0f, SquareRoot32(memory, state, FExtractV32(src2, 1))));
  FWriteV32(dst, out);
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(PFACC, D dst, S1 src_dst, S2 src) {
  auto src1 = FReadV32(src_dst);
  auto src2 = FReadV32(src);
  auto out = FClearV32(FReadV32(dst));
  out = FInsertV32(out, 0, FAdd(FExtractV32(src1, 0), FExtractV32(src1, 1)));
  out = FInsertV32(out, 1, FAdd(FExtractV32(src2, 0), FExtractV32(src2, 1)));
  FWriteV32(dst, out);
  return memory;
}

}  // namespace

DEF_ISEL(PFMUL_MMXq_MEMq) = PFMUL<V64W, V64, MV64>;
DEF_ISEL(PFMUL_MMXq_MMXq) = PFMUL<V64W, V64, V64>;
DEF_ISEL(PFADD_MMXq_MEMq) = PFADD<V64W, V64, MV64>;
DEF_ISEL(PFADD_MMXq_MMXq) = PFADD<V64W, V64, V64>;
DEF_ISEL(PFSUB_MMXq_MEMq) = PFSUB<V64W, V64, MV64>;
DEF_ISEL(PFSUB_MMXq_MMXq) = PFSUB<V64W, V64, V64>;
DEF_ISEL(PFSUBR_MMXq_MEMq) = PFSUBR<V64W, V64, MV64>;
DEF_ISEL(PFSUBR_MMXq_MMXq) = PFSUBR<V64W, V64, V64>;
DEF_ISEL(PFMAX_MMXq_MEMq) = PFMAX<V64W, V64, MV64>;
DEF_ISEL(PFMAX_MMXq_MMXq) = PFMAX<V64W, V64, V64>;
DEF_ISEL(PFMIN_MMXq_MEMq) = PFMIN<V64W, V64, MV64>;
DEF_ISEL(PFMIN_MMXq_MMXq) = PFMIN<V64W, V64, V64>;
DEF_ISEL(PFCMPGT_MMXq_MEMq) = PFCMPGT<V64W, V64, MV64>;
DEF_ISEL(PFCMPGT_MMXq_MMXq) = PFCMPGT<V64W, V64, V64>;
DEF_ISEL(PFCMPGE_MMXq_MEMq) = PFCMPGE<V64W, V64, MV64>;
DEF_ISEL(PFCMPGE_MMXq_MMXq) = PFCMPGE<V64W, V64, V64>;
DEF_ISEL(PFCMPEQ_MMXq_MEMq) = PFCMPEQ<V64W, V64, MV64>;
DEF_ISEL(PFCMPEQ_MMXq_MMXq) = PFCMPEQ<V64W, V64, V64>;
DEF_ISEL(PFRSQRT_MMXq_MEMq) = PFRSQRT<V64W, V64, MV64>;
DEF_ISEL(PFRSQRT_MMXq_MMXq) = PFRSQRT<V64W, V64, V64>;
DEF_ISEL(PFACC_MMXq_MEMq) = PFACC<V64W, V64, MV64>;
DEF_ISEL(PFACC_MMXq_MMXq) = PFACC<V64W, V64, V64>;

/*
5547 VPINSRW VPINSRW_XMMu16_XMMu16_GPR32u16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_128N ATTRIBUTES:
5548 VPINSRW VPINSRW_XMMu16_XMMu16_MEMu16_IMM8_AVX512 AVX512 AVX512EVEX AVX512BW_128N ATTRIBUTES: DISP8_GPR_READER_WORD
 */

DEF_ISEL(MOVNTQ_MEMq_MMXq) = DoMOVNTQ_MEMq_MMXq;

DEF_ISEL(MASKMOVQ_MMXq_MMXq) = DoMASKMOVQ_MMXq_MMXq;

DEF_ISEL(EMMS) = DoEMMS;

DEF_ISEL(FEMMS) = DoEMMS;

/*
1251 CVTTPS2PI CVTTPS2PI_MMXq_MEMq CONVERT SSE SSE ATTRIBUTES: MMX_EXCEPT MXCSR NOTSX
1252 CVTTPS2PI CVTTPS2PI_MMXq_XMMq CONVERT SSE SSE ATTRIBUTES: MMX_EXCEPT MXCSR NOTSX

1423 CVTPS2PI CVTPS2PI_MMXq_MEMq CONVERT SSE SSE ATTRIBUTES: MMX_EXCEPT MXCSR NOTSX
1424 CVTPS2PI CVTPS2PI_MMXq_XMMq CONVERT SSE SSE ATTRIBUTES: MMX_EXCEPT MXCSR NOTSX

1681 CVTPD2PI CVTPD2PI_MMXq_MEMpd CONVERT SSE2 SSE2 ATTRIBUTES: MMX_EXCEPT MXCSR NOTSX REQUIRES_ALIGNMENT SIMD_PACKED_ALIGNMENT
1682 CVTPD2PI CVTPD2PI_MMXq_XMMpd CONVERT SSE2 SSE2 ATTRIBUTES: MMX_EXCEPT MXCSR NOTSX REQUIRES_ALIGNMENT SIMD_PACKED_ALIGNMENT

1918 CVTTPD2PI CVTTPD2PI_MMXq_MEMpd CONVERT SSE2 SSE2 ATTRIBUTES: MMX_EXCEPT MXCSR NOTSX REQUIRES_ALIGNMENT SIMD_PACKED_ALIGNMENT
1919 CVTTPD2PI CVTTPD2PI_MMXq_XMMpd CONVERT SSE2 SSE2 ATTRIBUTES: MMX_EXCEPT MXCSR NOTSX REQUIRES_ALIGNMENT SIMD_PACKED_ALIGNMENT

 */

// 565:117 PHSUBD PHSUBD_MMXq_MEMq MMX SSSE3 SSSE3 ATTRIBUTES: NOTSX
// 569:118 PHSUBD PHSUBD_MMXq_MMXq MMX SSSE3 SSSE3 ATTRIBUTES: NOTSX
// 639:135 PMULHRSW PMULHRSW_MMXq_MEMq MMX SSSE3 SSSE3 ATTRIBUTES: NOTSX
// 643:136 PMULHRSW PMULHRSW_MMXq_MMXq MMX SSSE3 SSSE3 ATTRIBUTES: NOTSX
// 671:143 PHSUBW PHSUBW_MMXq_MEMq MMX SSSE3 SSSE3 ATTRIBUTES: NOTSX
// 675:144 PHSUBW PHSUBW_MMXq_MMXq MMX SSSE3 SSSE3 ATTRIBUTES: NOTSX

// 1077:235 PACKUSWB PACKUSWB_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: HALF_WIDE_OUTPUT NOTSX
// 1081:236 PACKUSWB PACKUSWB_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: HALF_WIDE_OUTPUT NOTSX

// 1584:353 PSUBD PSUBD_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 1588:354 PSUBD PSUBD_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 1925:425 PSADBW PSADBW_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 1929:426 PSADBW PSADBW_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 2197:482 PADDUSW PADDUSW_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 2201:483 PADDUSW PADDUSW_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 2239:490 PMADDUBSW PMADDUBSW_MMXq_MEMq MMX SSSE3 SSSE3 ATTRIBUTES: DOUBLE_WIDE_OUTPUT NOTSX
// 2243:491 PMADDUBSW PMADDUBSW_MMXq_MMXq MMX SSSE3 SSSE3 ATTRIBUTES: DOUBLE_WIDE_OUTPUT NOTSX
// 2283:498 PADDUSB PADDUSB_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 2287:499 PADDUSB PADDUSB_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 2437:533 PACKSSDW PACKSSDW_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: HALF_WIDE_OUTPUT NOTSX
// 2441:534 PACKSSDW PACKSSDW_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: HALF_WIDE_OUTPUT NOTSX
// 2460:539 PMULLW PMULLW_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 2464:540 PMULLW PMULLW_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 2498:549 PHSUBSW PHSUBSW_MMXq_MEMq MMX SSSE3 SSSE3 ATTRIBUTES: NOTSX
// 2502:550 PHSUBSW PHSUBSW_MMXq_MMXq MMX SSSE3 SSSE3 ATTRIBUTES: NOTSX

// 2760:605 PADDSW PADDSW_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 2764:606 PADDSW PADDSW_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 2807:616 PXOR PXOR_MMXq_MEMq LOGICAL MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 2811:617 PXOR PXOR_MMXq_MMXq LOGICAL MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 3203:700 PSUBB PSUBB_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 3207:701 PSUBB PSUBB_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 3267:714 PSUBUSW PSUBUSW_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 3271:715 PSUBUSW PSUBUSW_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 3288:719 PSUBW PSUBW_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 3292:720 PSUBW PSUBW_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 3460:753 PADDW PADDW_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 3464:754 PADDW PADDW_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 3476:757 PMAXSW PMAXSW_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 3480:758 PMAXSW PMAXSW_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 3620:787 PADDD PADDD_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 3624:788 PADDD PADDD_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 3644:793 PADDB PADDB_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 3648:794 PADDB PADDB_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 3766:820 PADDQ PADDQ_MMXq_MEMq MMX SSE2 SSE2 ATTRIBUTES: NOTSX
// 3770:821 PADDQ PADDQ_MMXq_MMXq MMX SSE2 SSE2 ATTRIBUTES: NOTSX
// 3858:842 PABSW PABSW_MMXq_MEMq MMX SSSE3 SSSE3 ATTRIBUTES: NOTSX
// 3862:843 PABSW PABSW_MMXq_MMXq MMX SSSE3 SSSE3 ATTRIBUTES: NOTSX
// 4019:876 PMULHUW PMULHUW_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 4023:877 PMULHUW PMULHUW_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 4385:950 PSLLD PSLLD_MMXq_IMMb MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 4393:952 PSLLD PSLLD_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 4397:953 PSLLD PSLLD_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 4518:980 PSLLW PSLLW_MMXq_IMMb MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 4526:982 PSLLW PSLLW_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 4530:983 PSLLW PSLLW_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 4558:990 PSLLQ PSLLQ_MMXq_IMMb MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 4566:992 PSLLQ PSLLQ_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 4570:993 PSLLQ PSLLQ_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 4684:1017 PSUBUSB PSUBUSB_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 4688:1018 PSUBUSB PSUBUSB_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 4784:1038 PMOVMSKB PMOVMSKB_GPR32_MMXq MMX MMX SSE ATTRIBUTES: NOTSX

// 5203:1120 PALIGNR PALIGNR_MMXq_MEMq_IMMb MMX SSSE3 SSSE3 ATTRIBUTES: NOTSX
// 5208:1121 PALIGNR PALIGNR_MMXq_MMXq_IMMb MMX SSSE3 SSSE3 ATTRIBUTES: NOTSX
// 5258:1131 PMULHW PMULHW_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 5262:1132 PMULHW PMULHW_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 5374:1157 MOVQ MOVQ_MMXq_MEMq_0F6E DATAXFER MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 5378:1158 MOVQ MOVQ_MMXq_GPR64 DATAXFER MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 5382:1159 MOVQ MOVQ_MEMq_MMXq_0F7E DATAXFER MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 5386:1160 MOVQ MOVQ_GPR64_MMXq DATAXFER MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 5390:1161 MOVQ MOVQ_MMXq_MEMq_0F6F DATAXFER MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 5394:1162 MOVQ MOVQ_MMXq_MMXq_0F6F DATAXFER MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 5398:1163 MOVQ MOVQ_MEMq_MMXq_0F7F DATAXFER MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 5402:1164 MOVQ MOVQ_MMXq_MMXq_0F7F DATAXFER MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 5406:1165 PMINSW PMINSW_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 5410:1166 PMINSW PMINSW_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 5552:1196 PSHUFB PSHUFB_MMXq_MEMq MMX SSSE3 SSSE3 ATTRIBUTES: NOTSX
// 5556:1197 PSHUFB PSHUFB_MMXq_MMXq MMX SSSE3 SSSE3 ATTRIBUTES: NOTSX
// 5708:1234 PSHUFW PSHUFW_MMXq_MEMq_IMMb MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 5713:1235 PSHUFW PSHUFW_MMXq_MMXq_IMMb MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 5960:1291 PSRLQ PSRLQ_MMXq_IMMb MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 5968:1293 PSRLQ PSRLQ_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 5972:1294 PSRLQ PSRLQ_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 5984:1297 PSRLW PSRLW_MMXq_IMMb MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 5992:1299 PSRLW PSRLW_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 5996:1300 PSRLW PSRLW_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 6038:1310 PSRLD PSRLD_MMXq_IMMb MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 6046:1312 PSRLD PSRLD_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 6050:1313 PSRLD PSRLD_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 6385:1378 FEMMS FEMMS MMX 3DNOW 3DNOW ATTRIBUTES: X87_MMX_STATE_W
// 6393:1380 PADDSB PADDSB_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 6397:1381 PADDSB PADDSB_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 6723:1447 MOVD MOVD_MMXq_MEMd DATAXFER MMX PENTIUMMMX ATTRIBUTES: NOTSX UNALIGNED
// 6727:1448 MOVD MOVD_MMXq_GPR32 DATAXFER MMX PENTIUMMMX ATTRIBUTES: NOTSX UNALIGNED
// 6731:1449 MOVD MOVD_MMXq_MEMd DATAXFER MMX PENTIUMMMX ATTRIBUTES: NOTSX UNALIGNED
// 6735:1450 MOVD MOVD_MMXq_GPR32 DATAXFER MMX PENTIUMMMX ATTRIBUTES: NOTSX UNALIGNED
// 6739:1451 MOVD MOVD_MEMd_MMXd DATAXFER MMX PENTIUMMMX ATTRIBUTES: NOTSX UNALIGNED
// 6743:1452 MOVD MOVD_GPR32_MMXd DATAXFER MMX PENTIUMMMX ATTRIBUTES: NOTSX UNALIGNED
// 6747:1453 MOVD MOVD_MEMd_MMXd DATAXFER MMX PENTIUMMMX ATTRIBUTES: NOTSX UNALIGNED
// 6751:1454 MOVD MOVD_GPR32_MMXd DATAXFER MMX PENTIUMMMX ATTRIBUTES: NOTSX UNALIGNED
// 6907:1485 PABSD PABSD_MMXq_MEMq MMX SSSE3 SSSE3 ATTRIBUTES: NOTSX SIMD_SCALAR
// 6911:1486 PABSD PABSD_MMXq_MMXq MMX SSSE3 SSSE3 ATTRIBUTES: NOTSX SIMD_SCALAR
// 6930:1491 PABSB PABSB_MMXq_MEMq MMX SSSE3 SSSE3 ATTRIBUTES: NOTSX
// 6934:1492 PABSB PABSB_MMXq_MMXq MMX SSSE3 SSSE3 ATTRIBUTES: NOTSX
// 6956:1497 PSUBQ PSUBQ_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 6960:1498 PSUBQ PSUBQ_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 7020:1511 EMMS EMMS MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX X87_MMX_STATE_W

// 7126:1536 PHADDW PHADDW_MMXq_MEMq MMX SSSE3 SSSE3 ATTRIBUTES: NOTSX
// 7130:1537 PHADDW PHADDW_MMXq_MMXq MMX SSSE3 SSSE3 ATTRIBUTES: NOTSX
// 7448:1602 PMULUDQ PMULUDQ_MMXq_MEMq MMX SSE2 SSE2 ATTRIBUTES: NOTSX
// 7452:1603 PMULUDQ PMULUDQ_MMXq_MMXq MMX SSE2 SSE2 ATTRIBUTES: NOTSX
// 7479:1609 PMADDWD PMADDWD_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: DOUBLE_WIDE_OUTPUT NOTSX
// 7483:1610 PMADDWD PMADDWD_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: DOUBLE_WIDE_OUTPUT NOTSX
// 7527:1619 PEXTRW PEXTRW_GPR32_MMXq_IMMb MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 7605:1635 PAND PAND_MMXq_MEMq LOGICAL MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 7609:1636 PAND PAND_MMXq_MMXq LOGICAL MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 7669:1650 PMAXUB PMAXUB_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 7673:1651 PMAXUB PMAXUB_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX

//DEF_ISEL(PUNPCKHWD_MMXq_MEMq) = PUNPCKHBW<V64W, V64, MV64>;
//DEF_ISEL(PUNPCKHWD_MMXq_MMXd) = PUNPCKHBW<V64W, V64, V32>;

// 8028:1731 PMINUB PMINUB_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 8032:1732 PMINUB PMINUB_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 8050:1736 PINSRW PINSRW_MMXq_MEMw_IMMb MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX UNALIGNED
// 8055:1737 PINSRW PINSRW_MMXq_GPR32_IMMb MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX UNALIGNED
// 8162:1758 PSUBSW PSUBSW_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 8166:1759 PSUBSW PSUBSW_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 8194:1766 PAVGW PAVGW_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 8198:1767 PAVGW PAVGW_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 8404:1809 PSUBSB PSUBSB_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 8408:1810 PSUBSB PSUBSB_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 8474:1823 PAVGB PAVGB_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 8478:1824 PAVGB PAVGB_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 8498:1829 MASKMOVQ MASKMOVQ_MMXq_MMXq DATAXFER MMX PENTIUMMMX ATTRIBUTES: FIXED_BASE0 MASKOP NOTSX
// 8545:1840 PSRAW PSRAW_MMXq_IMMb MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 8553:1842 PSRAW PSRAW_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 8557:1843 PSRAW PSRAW_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 8587:1850 PSRAD PSRAD_MMXq_IMMb MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 8595:1852 PSRAD PSRAD_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 8599:1853 PSRAD PSRAD_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: NOTSX
// 8611:1856 PACKSSWB PACKSSWB_MMXq_MEMq MMX MMX PENTIUMMMX ATTRIBUTES: HALF_WIDE_OUTPUT NOTSX
// 8615:1857 PACKSSWB PACKSSWB_MMXq_MMXq MMX MMX PENTIUMMMX ATTRIBUTES: HALF_WIDE_OUTPUT NOTSX
