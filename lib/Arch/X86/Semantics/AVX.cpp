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

template <typename D, typename S1>
DEF_SEM(VPBROADCASTB, D dst, S1 src1) {
  auto src_vec = UReadV8(src1);
  auto dst_vec = UClearV8(UReadV8(dst));
  auto num_groups = NumVectorElems(dst_vec);
  auto src_byte = UExtractV8(src_vec, 0);

  for (std::size_t i = 0; i < num_groups; ++i) {
    dst_vec = UInsertV8(dst_vec, i, src_byte);
  }
  UWriteV8(dst, dst_vec);
  return memory;
}

template <typename D, typename S1>
DEF_SEM(VPBROADCASTQ, D dst, S1 src1) {
  auto src_vec = UReadV64(src1);
  auto dst_vec = UClearV64(UReadV64(dst));
  auto num_groups = NumVectorElems(dst_vec);
  auto src_val = UExtractV64(src_vec, 0);

  for (std::size_t i = 0; i < num_groups; ++i) {
    dst_vec = UInsertV64(dst_vec, i, src_val);
  }
  UWriteV64(dst, dst_vec);
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
MAKE_VMASKMOVx(32, 1) MAKE_VMASKMOVx(64, 1)
    // Suffix 0: store variant
    MAKE_VMASKMOVx(32, 0) MAKE_VMASKMOVx(64, 0)

}  // namespace

DEF_ISEL(VINSERTF128_YMMqq_YMMqq_MEMdq_IMMb) = VINSERTF128<MV128>;
DEF_ISEL(VINSERTF128_YMMqq_YMMqq_XMMdq_IMMb) = VINSERTF128<V128>;

DEF_ISEL(VZEROUPPER) = DoVZEROUPPER;
DEF_ISEL(VPBROADCASTB_YMMqq_XMMb) = VPBROADCASTB<VV256W, V128>;
DEF_ISEL(VPBROADCASTQ_YMMqq_XMMq) = VPBROADCASTQ<VV256W, V128>;

DEF_ISEL(VMASKMOVPS_XMMdq_XMMdq_MEMdq) = VMASKMOV32_1<VV128W, V128, MV128>;
DEF_ISEL(VMASKMOVPS_MEMdq_XMMdq_XMMdq) = VMASKMOV32_0<MV128W, V128, V128>;
DEF_ISEL(VMASKMOVPS_YMMqq_YMMqq_MEMqq) = VMASKMOV32_1<VV256W, V256, MV256>;
DEF_ISEL(VMASKMOVPS_MEMqq_YMMqq_YMMqq) = VMASKMOV32_0<MV256W, V256, V256>;

DEF_ISEL(VMASKMOVPD_XMMdq_XMMdq_MEMdq) = VMASKMOV64_1<VV128W, V128, MV128>;
DEF_ISEL(VMASKMOVPD_MEMdq_XMMdq_XMMdq) = VMASKMOV64_0<MV128W, V128, V128>;
DEF_ISEL(VMASKMOVPD_YMMqq_YMMqq_MEMqq) = VMASKMOV64_1<VV256W, V256, MV256>;
DEF_ISEL(VMASKMOVPD_MEMqq_YMMqq_YMMqq) = VMASKMOV64_0<MV256W, V256, V256>;

DEF_ISEL(VPMASKMOVD_XMMdq_XMMdq_MEMdq) = VMASKMOV32_1<VV128W, VV128, MV128>;
DEF_ISEL(VPMASKMOVD_MEMdq_XMMdq_XMMdq) = VMASKMOV32_0<MV128W, VV128, VV128>;
DEF_ISEL(VPMASKMOVD_YMMqq_YMMqq_MEMqq) = VMASKMOV32_1<VV256W, VV256, MV256>;
DEF_ISEL(VPMASKMOVD_MEMqq_YMMqq_YMMqq) = VMASKMOV32_0<MV256W, VV256, VV256>;

DEF_ISEL(VPMASKMOVQ_XMMdq_XMMdq_MEMdq) = VMASKMOV64_1<VV128W, VV128, MV128>;
DEF_ISEL(VPMASKMOVQ_MEMdq_XMMdq_XMMdq) = VMASKMOV64_0<MV128W, VV128, VV128>;
DEF_ISEL(VPMASKMOVQ_YMMqq_YMMqq_MEMqq) = VMASKMOV64_1<VV256W, VV256, MV256>;
DEF_ISEL(VPMASKMOVQ_MEMqq_YMMqq_YMMqq) = VMASKMOV64_0<MV256W, VV256, VV256>;


#endif  // HAS_FEATURE_AVX
