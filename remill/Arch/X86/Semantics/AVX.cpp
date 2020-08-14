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
}  //  namespace

namespace {

template <typename D, typename S1, size_t KL, size_t VL>
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

}  // namespace

DEF_ISEL(VZEROUPPER) = DoVZEROUPPER;
DEF_ISEL(VPBROADCASTB_YMMqq_XMMb) = VPBROADCASTB<VV256W, V128, 32, 256>;

#endif  // HAS_FEATURE_AVX
