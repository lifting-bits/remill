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

namespace {


template <typename S1, typename S2, typename D>
DEF_SEM(BMASK, S1 src1, S2 src2, D dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto sum = UAdd(lhs, rhs);
  auto mask = Literal<S1>(UNot(Literal<S1>(0)));
  GSR_MASK = mask;
  WriteZExt(dst, sum);
  return memory;
}

DEF_SEM(BSHUFFLE, V64 src1, V64 src2, V64W dst) {
  auto rs1_vec = UReadV8(src1);
  auto rs2_vec = UReadV8(src2);
  auto dst_vec = UClearV8(UReadV8(dst));
  auto mask = Read(GSR_MASK);

  auto num_elems = NumVectorElems(rs1_vec);
  _Pragma("unroll") for (size_t i = 0; i < NumVectorElems(dst_vec); ++i) {
    auto e = UShr(mask, decltype(mask)(28 - i * 4));
    auto index = UXor(e, Literal<decltype(e)>(0xff));
    if (index >= num_elems) {
      dst_vec = UInsertV8(dst_vec, num_elems - i,
                          UExtractV8(rs2_vec, (2 * num_elems - 1) - index));
    } else {
      dst_vec = UInsertV8(dst_vec, num_elems - i,
                          UExtractV8(rs2_vec, (num_elems - 1) - index));
    }
  }
  UWriteV8(dst, dst_vec);
  return memory;
}

}  // namespace

DEF_ISEL(BMASK) = BMASK<R64, R64, R64W>;
DEF_ISEL(BSHUFFLE) = BSHUFFLE;
