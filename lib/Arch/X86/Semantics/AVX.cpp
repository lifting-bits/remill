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

#if HAS_FEATURE_AVX

namespace {

DEF_SEM(DoVZEROUPPER) {
  _Pragma("unroll") for (unsigned i = 0; i < IF_64BIT_ELSE(16, 8); ++i) {
    auto &vec = state.vec[i];
    vec.ymm.dqwords.elems[1] = 0;
    IF_AVX512(vec.zmm.dqwords.elems[2] = 0;)
    IF_AVX512(vec.zmm.dqwords.elems[3] = 0;)
  }
  return memory;
}

template <typename S2>
DEF_SEM(VINSERTF128, VV256W dst, V256 src1, S2 src2, I8 src3) {
  auto dst_vec = UReadV128(src1);
  auto src2_vec = UReadV128(src2);
  auto src3_i8 = Read(src3);
  auto i = static_cast<unsigned>(src3_i8 & 1u);
  dst_vec = UInsertV128(dst_vec, i, UExtractV128(src2_vec, 0));
  UWriteV128(dst, dst_vec);
  return memory;
}

//template<typename S2>
//DEF_SEM(VINSERTF128, VV512W dst, V512 src1, S2 src2, I8 src3) {
//  auto dst_vec = UReadV128(src1);
//  auto src2_vec = UReadV128(src2);
//  auto src3_i8 = Read(src3);
//  std::size_t i = static_cast<unsigned>(src3_i8 & 3u);
//  dst_vec  = UInsertV128(dst_vec, i, UExtractV128(src2_vec, 0));
//  UWriteV128(dst, dst_vec);
//  return memory;
//}
}  // namespace

DEF_ISEL(VINSERTF128_YMMqq_YMMqq_MEMdq_IMMb) = VINSERTF128<MV128>;
DEF_ISEL(VINSERTF128_YMMqq_YMMqq_XMMdq_IMMb) = VINSERTF128<V128>;

DEF_ISEL(VZEROUPPER) = DoVZEROUPPER;

namespace {

// U<ops> should be fine also for floating-point values as we just want to
// copy them
#  define MAKE_VBROADCASTx_imm(suffix, element_size, \
                               br_num /*Number of copies in dst */) \
    template <typename D, typename S1> \
    DEF_SEM(VBROADCAST##suffix##_##br_num, D dst, S1 src1) { \
      auto src_val = Read(src1); \
      auto dst_vec = UClearV##element_size(UReadV##element_size(dst)); \
\
      _Pragma("unroll") for (auto i = 0u; i < br_num; ++i) { \
        dst_vec = UInsertV##element_size(dst_vec, i, src_val); \
      } \
      UWriteV##element_size(dst, dst_vec); \
      return memory; \
    }

// When HAS_FEATURE_AVX is enabled, we cannot distinguish between VEX.128 and VEX.256
// by examining type D. Thus, hardcode the number of locations of the copy
MAKE_VBROADCASTx_imm(SS, 32, 4);
MAKE_VBROADCASTx_imm(SS, 32, 8);
MAKE_VBROADCASTx_imm(SD, 64, 4);
MAKE_VBROADCASTx_imm(F128, 128, 2);

MAKE_VBROADCASTx_imm(B, 8, 16);
MAKE_VBROADCASTx_imm(B, 8, 32);
MAKE_VBROADCASTx_imm(W, 16, 8);
MAKE_VBROADCASTx_imm(W, 16, 16);
MAKE_VBROADCASTx_imm(D, 32, 4);
MAKE_VBROADCASTx_imm(D, 32, 8);
MAKE_VBROADCASTx_imm(Q, 64, 2);
MAKE_VBROADCASTx_imm(Q, 64, 4);

#  undef MAKE_VBROADCASTx_imm

#  define MAKE_VBROADCASTx_vec(suffix, element_size, \
                               br_num /*Number of copies in dst */) \
    template <typename D> \
    DEF_SEM(VBROADCAST##suffix##_##br_num, D dst, V128 src1) { \
      auto src_vec = UReadV##element_size(src1); \
      auto src_val = UExtractV##element_size(src_vec, 0); \
      auto dst_vec = UClearV##element_size(UReadV##element_size(dst)); \
\
      _Pragma("unroll") for (auto i = 0u; i < br_num; ++i) { \
        dst_vec = UInsertV##element_size(dst_vec, i, src_val); \
      } \
      UWriteV##element_size(dst, dst_vec); \
      return memory; \
    }
MAKE_VBROADCASTx_vec(SS, 32, 4);
MAKE_VBROADCASTx_vec(SS, 32, 8);
MAKE_VBROADCASTx_vec(SD, 64, 4);
MAKE_VBROADCASTx_vec(F128, 128, 2);

MAKE_VBROADCASTx_vec(B, 8, 16);
MAKE_VBROADCASTx_vec(B, 8, 32);
MAKE_VBROADCASTx_vec(W, 16, 8);
MAKE_VBROADCASTx_vec(W, 16, 16);
MAKE_VBROADCASTx_vec(D, 32, 4);
MAKE_VBROADCASTx_vec(D, 32, 8);
MAKE_VBROADCASTx_vec(Q, 64, 2);
MAKE_VBROADCASTx_vec(Q, 64, 4);

#  undef MAKE_VBROADCASTx_vec


}  // namespace
DEF_ISEL(VPBROADCASTB_XMMdq_MEMb) = VBROADCASTB_16<VV128W, M8>;
DEF_ISEL(VPBROADCASTB_YMMqq_MEMb) = VBROADCASTB_32<VV256W, M8>;
DEF_ISEL(VPBROADCASTB_XMMdq_XMMb) = VBROADCASTB_16<VV128W>;
DEF_ISEL(VPBROADCASTB_YMMqq_XMMb) = VBROADCASTB_32<VV256W>;

DEF_ISEL(VPBROADCASTW_XMMdq_MEMw) = VBROADCASTW_8<VV128W, M16>;
DEF_ISEL(VPBROADCASTW_YMMqq_MEMw) = VBROADCASTW_16<VV256W, M16>;
DEF_ISEL(VPBROADCASTW_XMMdq_XMMw) = VBROADCASTW_8<VV128W>;
DEF_ISEL(VPBROADCASTW_YMMqq_XMMw) = VBROADCASTW_16<VV256W>;

DEF_ISEL(VPBROADCASTD_XMMdq_MEMd) = VBROADCASTD_4<VV128W, M32>;
DEF_ISEL(VPBROADCASTD_YMMqq_MEMd) = VBROADCASTD_8<VV256W, M32>;
DEF_ISEL(VPBROADCASTD_XMMdq_XMMd) = VBROADCASTD_4<VV128W>;
DEF_ISEL(VPBROADCASTD_YMMqq_XMMd) = VBROADCASTD_8<VV256W>;

DEF_ISEL(VPBROADCASTQ_XMMdq_MEMq) = VBROADCASTQ_2<VV128W, M64>;
DEF_ISEL(VPBROADCASTQ_YMMqq_MEMq) = VBROADCASTQ_4<VV256W, M64>;
DEF_ISEL(VPBROADCASTQ_XMMdq_XMMq) = VBROADCASTQ_2<VV128W>;
DEF_ISEL(VPBROADCASTQ_YMMqq_XMMq) = VBROADCASTQ_4<VV256W>;

DEF_ISEL(VBROADCASTSS_XMMdq_MEMd) = VBROADCASTSS_4<VV128W, M32>;
DEF_ISEL(VBROADCASTSS_YMMqq_MEMd) = VBROADCASTSS_8<VV256W, M32>;
DEF_ISEL(VBROADCASTSS_XMMdq_XMMdq) = VBROADCASTSS_4<VV128W>;
DEF_ISEL(VBROADCASTSS_YMMqq_XMMdq) = VBROADCASTSS_8<VV256W>;

DEF_ISEL(VBROADCASTSD_YMMqq_MEMq) = VBROADCASTSD_4<VV256W, M64>;
DEF_ISEL(VBROADCASTSD_YMMqq_XMMdq) = VBROADCASTSD_4<VV256W>;

DEF_ISEL(VBROADCASTF128_YMMqq_MEMdq) = VBROADCASTF128_2<VV256W, M128>;
DEF_ISEL(VBROADCASTI128_YMMqq_MEMdq) = VBROADCASTF128_2<VV256W, M128>;

namespace {
#  define MAKE_VMASKMOVx(chunk_size, is_load) \
    template <typename D, typename M, typename S> \
    DEF_SEM(VMASKMOV##chunk_size##_##is_load, D dst, M mask, S src) { \
      auto dst_vec = UReadV##chunk_size(dst); \
      if (is_load) { \
        dst_vec = UClearV##chunk_size(dst_vec); \
      } \
      auto src_vec = UReadV##chunk_size(src); \
      auto mask_vec = UReadV##chunk_size(mask); \
      auto vec_count = NumVectorElems(src_vec); \
      _Pragma("unroll") for (size_t index = 0; index < vec_count; index++) { \
        auto mask_chunk = UExtractV##chunk_size(mask_vec, index); \
        auto src_chunk = UExtractV##chunk_size(src_vec, index); \
        auto dst_chunk = UExtractV##chunk_size(dst_vec, index); \
        auto new_chunk = Select(READBIT(mask_chunk, (chunk_size - 1)), \
                                src_chunk, dst_chunk); \
        dst_vec = UInsertV##chunk_size(dst_vec, index, new_chunk); \
      } \
      UWriteV##chunk_size(dst, dst_vec); \
      return memory; \
    }
// Suffix 1: load variant
MAKE_VMASKMOVx(32, 1) MAKE_VMASKMOVx(64, 1);
// Suffix 0: store variant
MAKE_VMASKMOVx(32, 0) MAKE_VMASKMOVx(64, 0);

#  undef MAKE_VMASKMOVx
}  // namespace


DEF_ISEL(VPMASKMOVD_XMMdq_XMMdq_MEMdq) = VMASKMOV32_1<VV128W, VV128, MV128>;
DEF_ISEL(VPMASKMOVD_MEMdq_XMMdq_XMMdq) = VMASKMOV32_0<MV128W, VV128, VV128>;
DEF_ISEL(VPMASKMOVD_YMMqq_YMMqq_MEMqq) = VMASKMOV32_1<VV256W, VV256, MV256>;
DEF_ISEL(VPMASKMOVD_MEMqq_YMMqq_YMMqq) = VMASKMOV32_0<MV256W, VV256, VV256>;

DEF_ISEL(VPMASKMOVQ_XMMdq_XMMdq_MEMdq) = VMASKMOV64_1<VV128W, VV128, MV128>;
DEF_ISEL(VPMASKMOVQ_MEMdq_XMMdq_XMMdq) = VMASKMOV64_0<MV128W, VV128, VV128>;
DEF_ISEL(VPMASKMOVQ_YMMqq_YMMqq_MEMqq) = VMASKMOV64_1<VV256W, VV256, MV256>;
DEF_ISEL(VPMASKMOVQ_MEMqq_YMMqq_YMMqq) = VMASKMOV64_0<MV256W, VV256, VV256>;


namespace {
#  define MAKE_VMASKMOVPx(chunk_size, is_load) \
    template <typename D, typename M, typename S> \
    DEF_SEM(VMASKMOVP##chunk_size##_##is_load, D dst, M mask, S src) { \
      auto dst_vec = FReadV##chunk_size(dst); \
      if (is_load) { \
        dst_vec = FClearV##chunk_size(dst_vec); \
      } \
      auto src_vec = FReadV##chunk_size(src); \
      auto mask_vec = UReadV##chunk_size(mask); \
      auto vec_count = NumVectorElems(src_vec); \
      _Pragma("unroll") for (size_t index = 0; index < vec_count; index++) { \
        auto mask_chunk = UExtractV##chunk_size(mask_vec, index); \
        auto src_chunk = FExtractV##chunk_size(src_vec, index); \
        auto dst_chunk = FExtractV##chunk_size(dst_vec, index); \
        auto new_chunk = Select(READBIT(mask_chunk, (chunk_size - 1)), \
                                src_chunk, dst_chunk); \
        dst_vec = FInsertV##chunk_size(dst_vec, index, new_chunk); \
      } \
      FWriteV##chunk_size(dst, dst_vec); \
      return memory; \
    }
// Suffix 1: load variant
MAKE_VMASKMOVPx(32, 1) MAKE_VMASKMOVPx(64, 1);
// Suffix 0: store variant
MAKE_VMASKMOVPx(32, 0) MAKE_VMASKMOVPx(64, 0);

#  undef MAKE_VMASKMOVPx
}  // namespace

DEF_ISEL(VMASKMOVPS_XMMdq_XMMdq_MEMdq) = VMASKMOVP32_1<VV128W, V128, MV128>;
DEF_ISEL(VMASKMOVPS_MEMdq_XMMdq_XMMdq) = VMASKMOVP32_0<MV128W, V128, V128>;
DEF_ISEL(VMASKMOVPS_YMMqq_YMMqq_MEMqq) = VMASKMOVP32_1<VV256W, V256, MV256>;
DEF_ISEL(VMASKMOVPS_MEMqq_YMMqq_YMMqq) = VMASKMOVP32_0<MV256W, V256, V256>;

DEF_ISEL(VMASKMOVPD_XMMdq_XMMdq_MEMdq) = VMASKMOVP64_1<VV128W, V128, MV128>;
DEF_ISEL(VMASKMOVPD_MEMdq_XMMdq_XMMdq) = VMASKMOVP64_0<MV128W, V128, V128>;
DEF_ISEL(VMASKMOVPD_YMMqq_YMMqq_MEMqq) = VMASKMOVP64_1<VV256W, V256, MV256>;
DEF_ISEL(VMASKMOVPD_MEMqq_YMMqq_YMMqq) = VMASKMOVP64_0<MV256W, V256, V256>;

#endif  // HAS_FEATURE_AVX
