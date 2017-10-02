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

namespace {

template <typename S>
DEF_SEM(ORR_Vec, V128W dst, S src1, S src2) {
  UWriteV64(dst, UOrV64(UReadV64(src1), UReadV64(src2)));
  return memory;
}

DEF_SEM(FMOV_VectorToUInt64, R64W dst, V128 src) {
  auto val = UExtractV64(UReadV64(src), 1);
  WriteZExt(dst, val);
  return memory;
}

DEF_SEM(FMOV_UInt64ToVector, V128W dst, R64 src) {
  auto val = Read(src);
  uint64v2_t temp_vec = {};
  temp_vec = UInsertV64(temp_vec, 0, UExtractV64(UReadV64(dst), 0));
  temp_vec = UInsertV64(temp_vec, 1, val);
  UWriteV64(dst, temp_vec);
  return memory;
}
}  // namespace

DEF_ISEL(ORR_ASIMDSAME_ONLY_8B) = ORR_Vec<V64>;
DEF_ISEL(ORR_ASIMDSAME_ONLY_16B) = ORR_Vec<V128>;

DEF_ISEL(FMOV_64VX_FLOAT2INT) = FMOV_VectorToUInt64;
DEF_ISEL(FMOV_V64I_FLOAT2INT) = FMOV_UInt64ToVector;
