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

namespace {

#define MAKE_DUP(size) \
    template <typename V> \
    DEF_SEM(DUP_ ## size, V128W dst, R64 src) { \
      auto val = TruncTo<uint ## size ## _t>(Read(src)); \
      V vec = {}; \
      for (auto &element : vec.elems) { \
        element = val; \
      } \
      UWriteV ## size(dst, vec); \
      return memory; \
    }

MAKE_DUP(8)
MAKE_DUP(16)
MAKE_DUP(32)
MAKE_DUP(64)

#undef MAKE_DUP

}  // namespace

DEF_ISEL(DUP_ASIMDINS_DR_R_8B) = DUP_8<uint8v8_t>;
DEF_ISEL(DUP_ASIMDINS_DR_R_16B) = DUP_8<uint8v16_t>;
DEF_ISEL(DUP_ASIMDINS_DR_R_4H) = DUP_16<uint16v4_t>;
DEF_ISEL(DUP_ASIMDINS_DR_R_8H) = DUP_16<uint16v8_t>;
DEF_ISEL(DUP_ASIMDINS_DR_R_2S) = DUP_32<uint32v2_t>;
DEF_ISEL(DUP_ASIMDINS_DR_R_4S) = DUP_32<uint32v4_t>;
DEF_ISEL(DUP_ASIMDINS_DR_R_2D) = DUP_64<uint64v2_t>;

namespace {

#define MAKE_BROADCAST(op, prefix, binop, size) \
    template <typename S, typename V> \
    DEF_SEM(op ## _ ## size, V128W dst, S src1, S src2) { \
      auto vec1 = prefix ## ReadV ## size (src1); \
      auto vec2 = prefix ## ReadV ## size (src2); \
      V sum = {}; \
      for (size_t i = 0, max_i = NumVectorElems(sum); i < max_i; ++i) { \
        sum.elems[i] = binop(prefix ## ExtractV ## size(vec1, i), \
                             prefix ## ExtractV ## size(vec2, i)); \
      } \
      UWriteV ## size(dst, sum); \
      return memory; \
    }

MAKE_BROADCAST(ADD, U, UAdd, 8)
MAKE_BROADCAST(ADD, U, UAdd, 16)
MAKE_BROADCAST(ADD, U, UAdd, 32)
MAKE_BROADCAST(ADD, U, UAdd, 64)

MAKE_BROADCAST(SUB, U, USub, 8)
MAKE_BROADCAST(SUB, U, USub, 16)
MAKE_BROADCAST(SUB, U, USub, 32)
MAKE_BROADCAST(SUB, U, USub, 64)

#undef MAKE_BROADCAST

}  // namespace

DEF_ISEL(ADD_ASIMDSAME_ONLY_8B) = ADD_8<V64, uint8v8_t>;
DEF_ISEL(ADD_ASIMDSAME_ONLY_16B) = ADD_8<V128, uint8v16_t>;
DEF_ISEL(ADD_ASIMDSAME_ONLY_4H) = ADD_16<V64, uint16v4_t>;
DEF_ISEL(ADD_ASIMDSAME_ONLY_8H) = ADD_16<V128, uint16v8_t>;
DEF_ISEL(ADD_ASIMDSAME_ONLY_2S) = ADD_32<V64, uint32v2_t>;
DEF_ISEL(ADD_ASIMDSAME_ONLY_4S) = ADD_32<V128, uint32v4_t>;
DEF_ISEL(ADD_ASIMDSAME_ONLY_2D) = ADD_64<V128, uint64v2_t>;

DEF_ISEL(SUB_ASIMDSAME_ONLY_8B) = SUB_8<V64, uint8v8_t>;
DEF_ISEL(SUB_ASIMDSAME_ONLY_16B) = SUB_8<V128, uint8v16_t>;
DEF_ISEL(SUB_ASIMDSAME_ONLY_4H) = SUB_16<V64, uint16v4_t>;
DEF_ISEL(SUB_ASIMDSAME_ONLY_8H) = SUB_16<V128, uint16v8_t>;
DEF_ISEL(SUB_ASIMDSAME_ONLY_2S) = SUB_32<V64, uint32v2_t>;
DEF_ISEL(SUB_ASIMDSAME_ONLY_4S) = SUB_32<V128, uint32v4_t>;
DEF_ISEL(SUB_ASIMDSAME_ONLY_2D) = SUB_64<V128, uint64v2_t>;
