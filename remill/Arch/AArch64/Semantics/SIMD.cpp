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
  UWriteV8(dst, UOrV8(UReadV8(src1), UReadV8(src2)));
  return memory;
}

template <typename S>
DEF_SEM(AND_Vec, V128W dst, S src1, S src2) {
  UWriteV8(dst, UAndV8(UReadV8(src1), UReadV8(src2)));
  return memory;
}

}  // namespace

DEF_ISEL(ORR_ASIMDSAME_ONLY_8B) = ORR_Vec<V64>;
DEF_ISEL(ORR_ASIMDSAME_ONLY_16B) = ORR_Vec<V128>;

DEF_ISEL(AND_ASIMDSAME_ONLY_8B) = AND_Vec<V64>;
DEF_ISEL(AND_ASIMDSAME_ONLY_16B) = AND_Vec<V128>;

namespace {

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

DEF_ISEL(FMOV_64VX_FLOAT2INT) = FMOV_VectorToUInt64;
DEF_ISEL(FMOV_V64I_FLOAT2INT) = FMOV_UInt64ToVector;

namespace {

#define MAKE_DUP(size) \
    template <typename V> \
    DEF_SEM(DUP_ ## size, V128W dst, R64 src) { \
      auto val = TruncTo<uint ## size ## _t>(Read(src)); \
      V vec = {}; \
      _Pragma("unroll") \
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

template <typename T>
ALWAYS_INLINE static T UMin(T lhs, T rhs) {
  return lhs < rhs ? lhs : rhs;
}

template <typename T>
ALWAYS_INLINE static T UMax(T lhs, T rhs) {
  return lhs < rhs ? rhs : lhs;
}

#define SMin UMin
#define SMax UMax

#define MAKE_BROADCAST(op, prefix, binop, size) \
    template <typename S, typename V> \
    DEF_SEM(op ## _ ## size, V128W dst, S src1, S src2) { \
      auto vec1 = prefix ## ReadV ## size (src1); \
      auto vec2 = prefix ## ReadV ## size (src2); \
      V sum = {}; \
      _Pragma("unroll") \
      for (size_t i = 0, max_i = NumVectorElems(sum); i < max_i; ++i) { \
        sum.elems[i] = prefix ## binop(prefix ## ExtractV ## size(vec1, i), \
                                       prefix ## ExtractV ## size(vec2, i)); \
      } \
      prefix ## WriteV ## size(dst, sum); \
      return memory; \
    }

MAKE_BROADCAST(ADD, U, Add, 8)
MAKE_BROADCAST(ADD, U, Add, 16)
MAKE_BROADCAST(ADD, U, Add, 32)
MAKE_BROADCAST(ADD, U, Add, 64)

MAKE_BROADCAST(SUB, U, Sub, 8)
MAKE_BROADCAST(SUB, U, Sub, 16)
MAKE_BROADCAST(SUB, U, Sub, 32)
MAKE_BROADCAST(SUB, U, Sub, 64)

MAKE_BROADCAST(UMIN, U, Min, 8)
MAKE_BROADCAST(UMIN, U, Min, 16)
MAKE_BROADCAST(UMIN, U, Min, 32)

MAKE_BROADCAST(SMIN, S, Min, 8)
MAKE_BROADCAST(SMIN, S, Min, 16)
MAKE_BROADCAST(SMIN, S, Min, 32)

MAKE_BROADCAST(UMAX, U, Max, 8)
MAKE_BROADCAST(UMAX, U, Max, 16)
MAKE_BROADCAST(UMAX, U, Max, 32)

MAKE_BROADCAST(SMAX, S, Max, 8)
MAKE_BROADCAST(SMAX, S, Max, 16)
MAKE_BROADCAST(SMAX, S, Max, 32)

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

DEF_ISEL(UMIN_ASIMDSAME_ONLY_8B) = UMIN_8<V64, uint8v8_t>;
DEF_ISEL(UMIN_ASIMDSAME_ONLY_16B) = UMIN_8<V128, uint8v16_t>;
DEF_ISEL(UMIN_ASIMDSAME_ONLY_4H) = UMIN_16<V64, uint16v4_t>;
DEF_ISEL(UMIN_ASIMDSAME_ONLY_8H) = UMIN_16<V128, uint16v8_t>;
DEF_ISEL(UMIN_ASIMDSAME_ONLY_2S) = UMIN_32<V64, uint32v2_t>;
DEF_ISEL(UMIN_ASIMDSAME_ONLY_4S) = UMIN_32<V128, uint32v4_t>;

DEF_ISEL(UMAX_ASIMDSAME_ONLY_8B) = UMAX_8<V64, uint8v8_t>;
DEF_ISEL(UMAX_ASIMDSAME_ONLY_16B) = UMAX_8<V128, uint8v16_t>;
DEF_ISEL(UMAX_ASIMDSAME_ONLY_4H) = UMAX_16<V64, uint16v4_t>;
DEF_ISEL(UMAX_ASIMDSAME_ONLY_8H) = UMAX_16<V128, uint16v8_t>;
DEF_ISEL(UMAX_ASIMDSAME_ONLY_2S) = UMAX_32<V64, uint32v2_t>;
DEF_ISEL(UMAX_ASIMDSAME_ONLY_4S) = UMAX_32<V128, uint32v4_t>;

DEF_ISEL(SMIN_ASIMDSAME_ONLY_8B) = SMIN_8<V64, int8v8_t>;
DEF_ISEL(SMIN_ASIMDSAME_ONLY_16B) = SMIN_8<V128, int8v16_t>;
DEF_ISEL(SMIN_ASIMDSAME_ONLY_4H) = SMIN_16<V64, int16v4_t>;
DEF_ISEL(SMIN_ASIMDSAME_ONLY_8H) = SMIN_16<V128, int16v8_t>;
DEF_ISEL(SMIN_ASIMDSAME_ONLY_2S) = SMIN_32<V64, int32v2_t>;
DEF_ISEL(SMIN_ASIMDSAME_ONLY_4S) = SMIN_32<V128, int32v4_t>;

DEF_ISEL(SMAX_ASIMDSAME_ONLY_8B) = SMAX_8<V64, int8v8_t>;
DEF_ISEL(SMAX_ASIMDSAME_ONLY_16B) = SMAX_8<V128, int8v16_t>;
DEF_ISEL(SMAX_ASIMDSAME_ONLY_4H) = SMAX_16<V64, int16v4_t>;
DEF_ISEL(SMAX_ASIMDSAME_ONLY_8H) = SMAX_16<V128, int16v8_t>;
DEF_ISEL(SMAX_ASIMDSAME_ONLY_2S) = SMAX_32<V64, int32v2_t>;
DEF_ISEL(SMAX_ASIMDSAME_ONLY_4S) = SMAX_32<V128, int32v4_t>;

namespace {

#define MAKE_CMP_BROADCAST(op, prefix, binop, size) \
    template <typename S, typename V> \
    DEF_SEM(op ## _ ## size, V128W dst, S src1, I ## size imm) { \
      auto vec1 = prefix ## ReadV ## size (src1); \
      auto ucmp_val = Read(imm); \
      auto cmp_val = Signed(ucmp_val); \
      decltype(ucmp_val) zeros = 0; \
      decltype(ucmp_val) ones = ~zeros; \
      V res = {}; \
      _Pragma("unroll") \
      for (size_t i = 0, max_i = NumVectorElems(res); i < max_i; ++i) { \
        res.elems[i] = Select( \
            prefix ## binop(prefix ## ExtractV ## size(vec1, i), cmp_val), \
            ones, \
            zeros); \
      } \
      UWriteV ## size(dst, res); \
      return memory; \
    }

MAKE_CMP_BROADCAST(CMPEQ_IMM, S, CmpEq, 8)
MAKE_CMP_BROADCAST(CMPEQ_IMM, S, CmpEq, 16)
MAKE_CMP_BROADCAST(CMPEQ_IMM, S, CmpEq, 32)
MAKE_CMP_BROADCAST(CMPEQ_IMM, S, CmpEq, 64)

MAKE_CMP_BROADCAST(CMPLT_IMM, S, CmpLt, 8)
MAKE_CMP_BROADCAST(CMPLT_IMM, S, CmpLt, 16)
MAKE_CMP_BROADCAST(CMPLT_IMM, S, CmpLt, 32)
MAKE_CMP_BROADCAST(CMPLT_IMM, S, CmpLt, 64)

MAKE_CMP_BROADCAST(CMPLE_IMM, S, CmpLte, 8)
MAKE_CMP_BROADCAST(CMPLE_IMM, S, CmpLte, 16)
MAKE_CMP_BROADCAST(CMPLE_IMM, S, CmpLte, 32)
MAKE_CMP_BROADCAST(CMPLE_IMM, S, CmpLte, 64)

MAKE_CMP_BROADCAST(CMPGT_IMM, S, CmpGt, 8)
MAKE_CMP_BROADCAST(CMPGT_IMM, S, CmpGt, 16)
MAKE_CMP_BROADCAST(CMPGT_IMM, S, CmpGt, 32)
MAKE_CMP_BROADCAST(CMPGT_IMM, S, CmpGt, 64)

MAKE_CMP_BROADCAST(CMPGE_IMM, S, CmpGte, 8)
MAKE_CMP_BROADCAST(CMPGE_IMM, S, CmpGte, 16)
MAKE_CMP_BROADCAST(CMPGE_IMM, S, CmpGte, 32)
MAKE_CMP_BROADCAST(CMPGE_IMM, S, CmpGte, 64)

#undef MAKE_CMP_BROADCAST

}  // namespace

DEF_ISEL(CMEQ_ASIMDMISC_Z_8B) = CMPEQ_IMM_8<V64, uint8v8_t>;
DEF_ISEL(CMLT_ASIMDMISC_Z_8B) = CMPLT_IMM_8<V64, uint8v8_t>;
DEF_ISEL(CMLE_ASIMDMISC_Z_8B) = CMPLE_IMM_8<V64, uint8v8_t>;
DEF_ISEL(CMGT_ASIMDMISC_Z_8B) = CMPGT_IMM_8<V64, uint8v8_t>;
DEF_ISEL(CMGE_ASIMDMISC_Z_8B) = CMPGE_IMM_8<V64, uint8v8_t>;

DEF_ISEL(CMEQ_ASIMDMISC_Z_16B) = CMPEQ_IMM_8<V128, uint8v16_t>;
DEF_ISEL(CMLT_ASIMDMISC_Z_16B) = CMPLT_IMM_8<V128, uint8v16_t>;
DEF_ISEL(CMLE_ASIMDMISC_Z_16B) = CMPLE_IMM_8<V128, uint8v16_t>;
DEF_ISEL(CMGT_ASIMDMISC_Z_16B) = CMPGT_IMM_8<V128, uint8v16_t>;
DEF_ISEL(CMGE_ASIMDMISC_Z_16B) = CMPGE_IMM_8<V128, uint8v16_t>;

DEF_ISEL(CMEQ_ASIMDMISC_Z_4H) = CMPEQ_IMM_16<V64, uint16v4_t>;
DEF_ISEL(CMLT_ASIMDMISC_Z_4H) = CMPLT_IMM_16<V64, uint16v4_t>;
DEF_ISEL(CMLE_ASIMDMISC_Z_4H) = CMPLE_IMM_16<V64, uint16v4_t>;
DEF_ISEL(CMGT_ASIMDMISC_Z_4H) = CMPGT_IMM_16<V64, uint16v4_t>;
DEF_ISEL(CMGE_ASIMDMISC_Z_4H) = CMPGE_IMM_16<V64, uint16v4_t>;

DEF_ISEL(CMEQ_ASIMDMISC_Z_8H) = CMPEQ_IMM_16<V128, uint16v8_t>;
DEF_ISEL(CMLT_ASIMDMISC_Z_8H) = CMPLT_IMM_16<V128, uint16v8_t>;
DEF_ISEL(CMLE_ASIMDMISC_Z_8H) = CMPLE_IMM_16<V128, uint16v8_t>;
DEF_ISEL(CMGT_ASIMDMISC_Z_8H) = CMPGT_IMM_16<V128, uint16v8_t>;
DEF_ISEL(CMGE_ASIMDMISC_Z_8H) = CMPGE_IMM_16<V128, uint16v8_t>;

DEF_ISEL(CMEQ_ASIMDMISC_Z_2S) = CMPEQ_IMM_32<V64, uint32v2_t>;
DEF_ISEL(CMLT_ASIMDMISC_Z_2S) = CMPLT_IMM_32<V64, uint32v2_t>;
DEF_ISEL(CMLE_ASIMDMISC_Z_2S) = CMPLE_IMM_32<V64, uint32v2_t>;
DEF_ISEL(CMGT_ASIMDMISC_Z_2S) = CMPGT_IMM_32<V64, uint32v2_t>;
DEF_ISEL(CMGE_ASIMDMISC_Z_2S) = CMPGE_IMM_32<V64, uint32v2_t>;

DEF_ISEL(CMEQ_ASIMDMISC_Z_4S) = CMPEQ_IMM_32<V128, uint32v4_t>;
DEF_ISEL(CMLT_ASIMDMISC_Z_4S) = CMPLT_IMM_32<V128, uint32v4_t>;
DEF_ISEL(CMLE_ASIMDMISC_Z_4S) = CMPLE_IMM_32<V128, uint32v4_t>;
DEF_ISEL(CMGT_ASIMDMISC_Z_4S) = CMPGT_IMM_32<V128, uint32v4_t>;
DEF_ISEL(CMGE_ASIMDMISC_Z_4S) = CMPGE_IMM_32<V128, uint32v4_t>;

DEF_ISEL(CMEQ_ASIMDMISC_Z_1D) = CMPEQ_IMM_64<V64, uint64v1_t>;
DEF_ISEL(CMLT_ASIMDMISC_Z_1D) = CMPLT_IMM_64<V64, uint64v1_t>;
DEF_ISEL(CMLE_ASIMDMISC_Z_1D) = CMPLE_IMM_64<V64, uint64v1_t>;
DEF_ISEL(CMGT_ASIMDMISC_Z_1D) = CMPGT_IMM_64<V64, uint64v1_t>;
DEF_ISEL(CMGE_ASIMDMISC_Z_1D) = CMPGE_IMM_64<V64, uint64v1_t>;

DEF_ISEL(CMEQ_ASIMDMISC_Z_2D) = CMPEQ_IMM_64<V128, uint64v2_t>;
DEF_ISEL(CMLT_ASIMDMISC_Z_2D) = CMPLT_IMM_64<V128, uint64v2_t>;
DEF_ISEL(CMLE_ASIMDMISC_Z_2D) = CMPLE_IMM_64<V128, uint64v2_t>;
DEF_ISEL(CMGT_ASIMDMISC_Z_2D) = CMPGT_IMM_64<V128, uint64v2_t>;
DEF_ISEL(CMGE_ASIMDMISC_Z_2D) = CMPGE_IMM_64<V128, uint64v2_t>;

namespace {

#define MAKE_CMP_BROADCAST(op, prefix, binop, size) \
    template <typename S, typename V> \
    DEF_SEM(op ## _ ## size, V128W dst, S src1, S src2) { \
      auto vec1 = prefix ## ReadV ## size (src1); \
      auto vec2 = prefix ## ReadV ## size (src2); \
      uint ## size ## _t zeros = 0; \
      uint ## size ## _t ones = ~zeros; \
      V res = {}; \
      _Pragma("unroll") \
      for (size_t i = 0, max_i = NumVectorElems(res); i < max_i; ++i) { \
        res.elems[i] = Select( \
            prefix ## binop(prefix ## ExtractV ## size(vec1, i), \
                            prefix ## ExtractV ## size(vec2, i)), \
            ones, \
            zeros); \
      } \
      UWriteV ## size(dst, res); \
      return memory; \
    }

template <typename T>
ALWAYS_INLINE static bool UCmpTst(T lhs, T rhs) {
  return UCmpNeq(UAnd(lhs, rhs), T(0));
}

MAKE_CMP_BROADCAST(CMPEQ, S, CmpEq, 8)
MAKE_CMP_BROADCAST(CMPEQ, S, CmpEq, 16)
MAKE_CMP_BROADCAST(CMPEQ, S, CmpEq, 32)
MAKE_CMP_BROADCAST(CMPEQ, S, CmpEq, 64)

MAKE_CMP_BROADCAST(CMPTST, U, CmpTst, 8)
MAKE_CMP_BROADCAST(CMPTST, U, CmpTst, 16)
MAKE_CMP_BROADCAST(CMPTST, U, CmpTst, 32)
MAKE_CMP_BROADCAST(CMPTST, U, CmpTst, 64)

MAKE_CMP_BROADCAST(CMPGT, S, CmpGt, 8)
MAKE_CMP_BROADCAST(CMPGT, S, CmpGt, 16)
MAKE_CMP_BROADCAST(CMPGT, S, CmpGt, 32)
MAKE_CMP_BROADCAST(CMPGT, S, CmpGt, 64)

MAKE_CMP_BROADCAST(CMPGE, S, CmpGte, 8)
MAKE_CMP_BROADCAST(CMPGE, S, CmpGte, 16)
MAKE_CMP_BROADCAST(CMPGE, S, CmpGte, 32)
MAKE_CMP_BROADCAST(CMPGE, S, CmpGte, 64)

#undef MAKE_CMP_BROADCAST

}  // namespace

DEF_ISEL(CMEQ_ASIMDSAME_ONLY_8B) = CMPEQ_8<V64, uint8v8_t>;
DEF_ISEL(CMGT_ASIMDSAME_ONLY_8B) = CMPGT_8<V64, uint8v8_t>;
DEF_ISEL(CMGE_ASIMDSAME_ONLY_8B) = CMPGE_8<V64, uint8v8_t>;
DEF_ISEL(CMTST_ASIMDSAME_ONLY_8B) = CMPTST_8<V64, uint8v8_t>;

DEF_ISEL(CMEQ_ASIMDSAME_ONLY_16B) = CMPEQ_8<V128, uint8v16_t>;
DEF_ISEL(CMGT_ASIMDSAME_ONLY_16B) = CMPGT_8<V128, uint8v16_t>;
DEF_ISEL(CMGE_ASIMDSAME_ONLY_16B) = CMPGE_8<V128, uint8v16_t>;
DEF_ISEL(CMTST_ASIMDSAME_ONLY_16B) = CMPTST_8<V128, uint8v16_t>;

DEF_ISEL(CMEQ_ASIMDSAME_ONLY_4H) = CMPEQ_16<V64, uint16v4_t>;
DEF_ISEL(CMGT_ASIMDSAME_ONLY_4H) = CMPGT_16<V64, uint16v4_t>;
DEF_ISEL(CMGE_ASIMDSAME_ONLY_4H) = CMPGE_16<V64, uint16v4_t>;
DEF_ISEL(CMTST_ASIMDSAME_ONLY_4H) = CMPTST_16<V64, uint16v4_t>;

DEF_ISEL(CMEQ_ASIMDSAME_ONLY_8H) = CMPEQ_16<V128, uint16v8_t>;
DEF_ISEL(CMGT_ASIMDSAME_ONLY_8H) = CMPGT_16<V128, uint16v8_t>;
DEF_ISEL(CMGE_ASIMDSAME_ONLY_8H) = CMPGE_16<V128, uint16v8_t>;
DEF_ISEL(CMTST_ASIMDSAME_ONLY_8H) = CMPTST_16<V128, uint16v8_t>;

DEF_ISEL(CMEQ_ASIMDSAME_ONLY_2S) = CMPEQ_32<V64, uint32v2_t>;
DEF_ISEL(CMGT_ASIMDSAME_ONLY_2S) = CMPGT_32<V64, uint32v2_t>;
DEF_ISEL(CMGE_ASIMDSAME_ONLY_2S) = CMPGE_32<V64, uint32v2_t>;
DEF_ISEL(CMTST_ASIMDSAME_ONLY_2S) = CMPTST_32<V64, uint32v2_t>;

DEF_ISEL(CMEQ_ASIMDSAME_ONLY_4S) = CMPEQ_32<V128, uint32v4_t>;
DEF_ISEL(CMGT_ASIMDSAME_ONLY_4S) = CMPGT_32<V128, uint32v4_t>;
DEF_ISEL(CMGE_ASIMDSAME_ONLY_4S) = CMPGE_32<V128, uint32v4_t>;
DEF_ISEL(CMTST_ASIMDSAME_ONLY_4S) = CMPTST_32<V128, uint32v4_t>;

DEF_ISEL(CMEQ_ASIMDSAME_ONLY_2D) = CMPEQ_64<V128, uint64v2_t>;
DEF_ISEL(CMGT_ASIMDSAME_ONLY_2D) = CMPGT_64<V128, uint64v2_t>;
DEF_ISEL(CMGE_ASIMDSAME_ONLY_2D) = CMPGE_64<V128, uint64v2_t>;
DEF_ISEL(CMTST_ASIMDSAME_ONLY_2D) = CMPTST_64<V128, uint64v2_t>;

namespace {

#define MAKE_PAIRWAISE_BROADCAST(op, prefix, binop, size) \
    template <typename S, typename V> \
    DEF_SEM(op ## _ ## size, V128W dst, S src1, S src2) { \
      auto vec1 = prefix ## ReadV ## size (src1); \
      auto vec2 = prefix ## ReadV ## size (src2); \
      V res = {}; \
      size_t max_i = NumVectorElems(res); \
      size_t j = 0; \
      _Pragma("unroll") \
      for (size_t i = 0; i < max_i; i += 2) { \
        res.elems[j++] = prefix ## binop( \
            prefix ## ExtractV ## size(vec1, i), \
            prefix ## ExtractV ## size(vec1, i + 1)); \
      } \
      _Pragma("unroll") \
      for (size_t i = 0; i < max_i; i += 2) { \
        res.elems[j++] = prefix ## binop( \
            prefix ## ExtractV ## size(vec2, i), \
            prefix ## ExtractV ## size(vec2, i + 1)); \
      } \
      prefix ## WriteV ## size(dst, res); \
      return memory; \
    }

MAKE_PAIRWAISE_BROADCAST(ADDP, U, Add, 8)
MAKE_PAIRWAISE_BROADCAST(ADDP, U, Add, 16)
MAKE_PAIRWAISE_BROADCAST(ADDP, U, Add, 32)
MAKE_PAIRWAISE_BROADCAST(ADDP, U, Add, 64)

MAKE_PAIRWAISE_BROADCAST(UMAXP, U, Max, 8)
MAKE_PAIRWAISE_BROADCAST(UMAXP, U, Max, 16)
MAKE_PAIRWAISE_BROADCAST(UMAXP, U, Max, 32)

MAKE_PAIRWAISE_BROADCAST(SMAXP, S, Max, 8)
MAKE_PAIRWAISE_BROADCAST(SMAXP, S, Max, 16)
MAKE_PAIRWAISE_BROADCAST(SMAXP, S, Max, 32)

MAKE_PAIRWAISE_BROADCAST(UMINP, U, Min, 8)
MAKE_PAIRWAISE_BROADCAST(UMINP, U, Min, 16)
MAKE_PAIRWAISE_BROADCAST(UMINP, U, Min, 32)

MAKE_PAIRWAISE_BROADCAST(SMINP, S, Min, 8)
MAKE_PAIRWAISE_BROADCAST(SMINP, S, Min, 16)
MAKE_PAIRWAISE_BROADCAST(SMINP, S, Min, 32)

#undef MAKE_PAIRWAISE_BROADCAST

}  // namespace

DEF_ISEL(ADDP_ASIMDSAME_ONLY_8B) = ADDP_8<V64, uint8v8_t>;
DEF_ISEL(ADDP_ASIMDSAME_ONLY_16B) = ADDP_8<V128, uint8v16_t>;
DEF_ISEL(ADDP_ASIMDSAME_ONLY_4H) = ADDP_16<V64, uint16v4_t>;
DEF_ISEL(ADDP_ASIMDSAME_ONLY_8H) = ADDP_16<V128, uint16v8_t>;
DEF_ISEL(ADDP_ASIMDSAME_ONLY_2S) = ADDP_32<V64, uint32v2_t>;
DEF_ISEL(ADDP_ASIMDSAME_ONLY_4S) = ADDP_32<V128, uint32v4_t>;
DEF_ISEL(ADDP_ASIMDSAME_ONLY_2D) = ADDP_64<V128, uint64v2_t>;

DEF_ISEL(UMINP_ASIMDSAME_ONLY_8B) = UMINP_8<V64, uint8v8_t>;
DEF_ISEL(UMINP_ASIMDSAME_ONLY_16B) = UMINP_8<V128, uint8v16_t>;
DEF_ISEL(UMINP_ASIMDSAME_ONLY_4H) = UMINP_16<V64, uint16v4_t>;
DEF_ISEL(UMINP_ASIMDSAME_ONLY_8H) = UMINP_16<V128, uint16v8_t>;
DEF_ISEL(UMINP_ASIMDSAME_ONLY_2S) = UMINP_32<V64, uint32v2_t>;
DEF_ISEL(UMINP_ASIMDSAME_ONLY_4S) = UMINP_32<V128, uint32v4_t>;

DEF_ISEL(UMAXP_ASIMDSAME_ONLY_8B) = UMAXP_8<V64, uint8v8_t>;
DEF_ISEL(UMAXP_ASIMDSAME_ONLY_16B) = UMAXP_8<V128, uint8v16_t>;
DEF_ISEL(UMAXP_ASIMDSAME_ONLY_4H) = UMAXP_16<V64, uint16v4_t>;
DEF_ISEL(UMAXP_ASIMDSAME_ONLY_8H) = UMAXP_16<V128, uint16v8_t>;
DEF_ISEL(UMAXP_ASIMDSAME_ONLY_2S) = UMAXP_32<V64, uint32v2_t>;
DEF_ISEL(UMAXP_ASIMDSAME_ONLY_4S) = UMAXP_32<V128, uint32v4_t>;

DEF_ISEL(SMINP_ASIMDSAME_ONLY_8B) = SMINP_8<V64, int8v8_t>;
DEF_ISEL(SMINP_ASIMDSAME_ONLY_16B) = SMINP_8<V128, int8v16_t>;
DEF_ISEL(SMINP_ASIMDSAME_ONLY_4H) = SMINP_16<V64, int16v4_t>;
DEF_ISEL(SMINP_ASIMDSAME_ONLY_8H) = SMINP_16<V128, int16v8_t>;
DEF_ISEL(SMINP_ASIMDSAME_ONLY_2S) = SMINP_32<V64, int32v2_t>;
DEF_ISEL(SMINP_ASIMDSAME_ONLY_4S) = SMINP_32<V128, int32v4_t>;

DEF_ISEL(SMAXP_ASIMDSAME_ONLY_8B) = SMAXP_8<V64, int8v8_t>;
DEF_ISEL(SMAXP_ASIMDSAME_ONLY_16B) = SMAXP_8<V128, int8v16_t>;
DEF_ISEL(SMAXP_ASIMDSAME_ONLY_4H) = SMAXP_16<V64, int16v4_t>;
DEF_ISEL(SMAXP_ASIMDSAME_ONLY_8H) = SMAXP_16<V128, int16v8_t>;
DEF_ISEL(SMAXP_ASIMDSAME_ONLY_2S) = SMAXP_32<V64, int32v2_t>;
DEF_ISEL(SMAXP_ASIMDSAME_ONLY_4S) = SMAXP_32<V128, int32v4_t>;
