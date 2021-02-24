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

DEF_SEM(ALIGNADDRESS, R64 src1, R64 src2, R64W dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto sum = UAdd(lhs, rhs);
  auto mask = static_cast<uint64_t>(0x7);
  GSR_ALIGN = UAnd(sum, mask);
  auto res = UAnd(sum, UNot(mask));
  WriteZExt(dst, res);
  return memory;
}

DEF_SEM(ALIGNADDRESS_LITTLE, R64 src1, R64 src2, R64W dst) {
  auto lhs = Read(src1);
  auto rhs = Read(src2);
  auto sum = UAdd(lhs, rhs);
  auto mask = Literal<decltype(sum)>(0x7);
  GSR_ALIGN = UNeg(UAnd(sum, mask));
  auto res = UAnd(sum, UNot(mask));
  WriteZExt(dst, res);
  return memory;
}

DEF_SEM(FALIGNDATAG, V128 src1, V128 src2, V128W dst) {

  // extract F[rs1] and F[rs2] and concat them
  auto rs1 = UReadV8(src1);
  auto rs2 = UReadV8(src2);
  auto concat_vec = UClearV8(UReadV8(dst));
  _Pragma("unroll") for (size_t i = 0; i < 8; ++i) {
    concat_vec = UInsertV8(concat_vec, i, UExtractV8(rs1, i));
  }
  _Pragma("unroll") for (size_t i = 0; i < 8; ++i) {
    concat_vec = UInsertV8(concat_vec, i, UExtractV8(rs2, i));
  }

  // Recover the vector from the GSR.align value
  auto align = Read(GSR_ALIGN);
  auto recv_vec = UClearV8(UReadV8(dst));
  _Pragma("unroll") for (size_t i = 0; i < 8; ++i) {
    recv_vec = UInsertV8(recv_vec, i, UExtractV8(concat_vec, align + i));
  }
  UWriteV8(dst, recv_vec);
  return memory;
}

}  // namespace

DEF_ISEL(ALIGNADDRESS) = ALIGNADDRESS;
DEF_ISEL(ALIGNADDRESS_LITTLE) = ALIGNADDRESS_LITTLE;
DEF_ISEL(FALIGNDATA) = FALIGNDATAG;
