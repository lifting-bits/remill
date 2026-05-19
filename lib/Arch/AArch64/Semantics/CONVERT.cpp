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

template <typename S, typename D>
ALWAYS_INLINE static D CheckedCast(State &state, S src) {
  return CheckedFloatUnaryOp(
      state, [](S v) { return static_cast<D>(v); }, src);
}

DEF_SEM(UCVTF_UInt32ToFloat32, V128W dst, R32 src) {
  auto res = CheckedCast<uint32_t, float32_t>(state, Read(src));
  FWriteV32(dst, res);
  return memory;
}

DEF_SEM(UCVTF_UInt32ToFloat64, V128W dst, R32 src) {
  auto res = CheckedCast<uint32_t, float64_t>(state, Read(src));
  FWriteV64(dst, res);
  return memory;
}

DEF_SEM(UCVTF_UInt64ToFloat32, V128W dst, R64 src) {
  auto res = CheckedCast<uint64_t, float32_t>(state, Read(src));
  FWriteV32(dst, res);
  return memory;
}

DEF_SEM(UCVTF_UInt64ToFloat64, V128W dst, R64 src) {
  auto res = CheckedCast<uint64_t, float64_t>(state, Read(src));
  FWriteV64(dst, res);
  return memory;
}

DEF_SEM(FCVTZU_Float32ToUInt32, R32W dst, V32 src) {
  auto float_val = FExtractV32(FReadV32(src), 0);
  auto res = CheckedCast<float32_t, uint32_t>(state, float_val);
  WriteZExt(dst, res);
  return memory;
}

DEF_SEM(FCVTZU_Float32ToUInt64, R64W dst, V32 src) {
  auto float_val = FExtractV32(FReadV32(src), 0);
  auto res = CheckedCast<float32_t, uint64_t>(state, float_val);
  WriteZExt(dst, res);
  return memory;
}

DEF_SEM(FCVTZU_Float64ToUInt32, R32W dst, V64 src) {
  auto float_val = FExtractV64(FReadV64(src), 0);
  auto res = CheckedCast<float64_t, uint32_t>(state, float_val);
  WriteZExt(dst, res);
  return memory;
}

DEF_SEM(FCVTZU_Float64ToUInt64, R64W dst, V64 src) {
  auto float_val = FExtractV64(FReadV64(src), 0);
  auto res = CheckedCast<float64_t, uint64_t>(state, float_val);
  WriteZExt(dst, res);
  return memory;
}

DEF_SEM(FCVTZS_Float32ToSInt32, R32W dst, V32 src) {
  auto float_val = FExtractV32(FReadV32(src), 0);
  auto res = CheckedCast<float32_t, int32_t>(state, float_val);
  WriteZExt(dst, res);
  return memory;
}

DEF_SEM(FCVTZS_Float64ToSInt32, R32W dst, V64 src) {
  auto float_val = FExtractV64(FReadV64(src), 0);
  auto res = CheckedCast<float64_t, int32_t>(state, float_val);
  WriteZExt(dst, res);
  return memory;
}

DEF_SEM(FCVTZS_Float64ToSInt64, R64W dst, V64 src) {
  auto float_val = FExtractV64(FReadV64(src), 0);
  auto res = CheckedCast<float64_t, int64_t>(state, float_val);
  WriteZExt(dst, res);
  return memory;
}

DEF_SEM(FCVTZS_Float32ToSInt64, R64W dst, V32 src) {
  auto float_val = FExtractV32(FReadV32(src), 0);
  auto res = CheckedCast<float32_t, int64_t>(state, float_val);
  WriteZExt(dst, res);
  return memory;
}

DEF_SEM(FCVT_Float32ToFloat64, V128W dst, V32 src) {
  auto float_val = FExtractV32(FReadV32(src), 0);
  auto res = CheckedCast<float32_t, float64_t>(state, float_val);
  FWriteV64(dst, res);
  return memory;
}

DEF_SEM(FCVT_Float64ToFloat32, V128W dst, V64 src) {
  auto float_val = FExtractV64(FReadV64(src), 0);
  auto res = CheckedCast<float64_t, float32_t>(state, float_val);
  FWriteV32(dst, res);
  return memory;
}
}  // namespace

// TODO(pag): UCVTF_H32_FLOAT2INT.
// TODO(pag): UCVTF_H64_FLOAT2INT.

DEF_ISEL(UCVTF_S32_FLOAT2INT) = UCVTF_UInt32ToFloat32;
DEF_ISEL(UCVTF_D32_FLOAT2INT) = UCVTF_UInt32ToFloat64;

DEF_ISEL(UCVTF_S64_FLOAT2INT) = UCVTF_UInt64ToFloat32;
DEF_ISEL(UCVTF_D64_FLOAT2INT) = UCVTF_UInt64ToFloat64;

DEF_ISEL(FCVTZU_64S_FLOAT2INT) = FCVTZU_Float32ToUInt64;
DEF_ISEL(FCVTZU_32S_FLOAT2INT) = FCVTZU_Float32ToUInt32;

DEF_ISEL(FCVTZU_32D_FLOAT2INT) = FCVTZU_Float64ToUInt32;
DEF_ISEL(FCVTZU_64D_FLOAT2INT) = FCVTZU_Float64ToUInt64;

DEF_ISEL(FCVTZS_32S_FLOAT2INT) = FCVTZS_Float32ToSInt32;

DEF_ISEL(FCVTZS_32D_FLOAT2INT) = FCVTZS_Float64ToSInt32;
DEF_ISEL(FCVTZS_64D_FLOAT2INT) = FCVTZS_Float64ToSInt64;
DEF_ISEL(FCVTZS_64S_FLOAT2INT) = FCVTZS_Float32ToSInt64;

namespace {

// FCVT with specific rounding modes — round float to int via the
// named rounding direction, then truncate to the destination integer
// type.
//   FCVTAS — Away from zero
//   FCVTNS — Nearest, ties to even
//   FCVTPS — to +Infinity (ceil)
//   FCVTMS — to -Infinity (floor)
//   *U variants produce unsigned destinations.
//
// remill's CONVERT.cpp ships only the truncate (FCVTZS/FCVTZU) forms;
// Rustc emits the rounding variants whenever it lowers
// `f32::round() as i32` / `as i64` and friends.

// Helper that applies a rounding-mode builtin then static_casts to
// the destination integer type. Defined per-mode/per-pair to avoid
// the WriteZExt macro getting confused by `<>` commas in template
// args.
#define DEFINE_ROUND_HELPER(name, round_builtin, Src, Dst, suffix) \
  ALWAYS_INLINE static Dst name##_cast_##suffix(State &state, Src v) { \
    return CheckedCast<Src, Dst>(state, round_builtin(v)); \
  }

#define DEFINE_ROUND_SEMS(name, round_builtin) \
  DEFINE_ROUND_HELPER(name, round_builtin, float32_t, int32_t,  F32_S32) \
  DEFINE_ROUND_HELPER(name, round_builtin, float32_t, int64_t,  F32_S64) \
  DEFINE_ROUND_HELPER(name, round_builtin, float64_t, int32_t,  F64_S32) \
  DEFINE_ROUND_HELPER(name, round_builtin, float64_t, int64_t,  F64_S64) \
  DEFINE_ROUND_HELPER(name, round_builtin, float32_t, uint32_t, F32_U32) \
  DEFINE_ROUND_HELPER(name, round_builtin, float32_t, uint64_t, F32_U64) \
  DEFINE_ROUND_HELPER(name, round_builtin, float64_t, uint32_t, F64_U32) \
  DEFINE_ROUND_HELPER(name, round_builtin, float64_t, uint64_t, F64_U64) \
  DEF_SEM(name##_F32_S32, R32W dst, V32 src) { \
    auto v = FExtractV32(FReadV32(src), 0); \
    auto r = name##_cast_F32_S32(state, v); \
    WriteZExt(dst, r); \
    return memory; \
  } \
  DEF_SEM(name##_F32_S64, R64W dst, V32 src) { \
    auto v = FExtractV32(FReadV32(src), 0); \
    auto r = name##_cast_F32_S64(state, v); \
    WriteZExt(dst, r); \
    return memory; \
  } \
  DEF_SEM(name##_F64_S32, R32W dst, V64 src) { \
    auto v = FExtractV64(FReadV64(src), 0); \
    auto r = name##_cast_F64_S32(state, v); \
    WriteZExt(dst, r); \
    return memory; \
  } \
  DEF_SEM(name##_F64_S64, R64W dst, V64 src) { \
    auto v = FExtractV64(FReadV64(src), 0); \
    auto r = name##_cast_F64_S64(state, v); \
    WriteZExt(dst, r); \
    return memory; \
  } \
  DEF_SEM(name##_F32_U32, R32W dst, V32 src) { \
    auto v = FExtractV32(FReadV32(src), 0); \
    auto r = name##_cast_F32_U32(state, v); \
    WriteZExt(dst, r); \
    return memory; \
  } \
  DEF_SEM(name##_F32_U64, R64W dst, V32 src) { \
    auto v = FExtractV32(FReadV32(src), 0); \
    auto r = name##_cast_F32_U64(state, v); \
    WriteZExt(dst, r); \
    return memory; \
  } \
  DEF_SEM(name##_F64_U32, R32W dst, V64 src) { \
    auto v = FExtractV64(FReadV64(src), 0); \
    auto r = name##_cast_F64_U32(state, v); \
    WriteZExt(dst, r); \
    return memory; \
  } \
  DEF_SEM(name##_F64_U64, R64W dst, V64 src) { \
    auto v = FExtractV64(FReadV64(src), 0); \
    auto r = name##_cast_F64_U64(state, v); \
    WriteZExt(dst, r); \
    return memory; \
  }

DEFINE_ROUND_SEMS(FCVTAS, __builtin_round)
DEFINE_ROUND_SEMS(FCVTNS, __builtin_nearbyint)
DEFINE_ROUND_SEMS(FCVTPS, __builtin_ceil)
DEFINE_ROUND_SEMS(FCVTMS, __builtin_floor)

#undef DEFINE_ROUND_SEMS
#undef DEFINE_ROUND_HELPER

}  // namespace

// FCVTAS — round Away → signed
DEF_ISEL(FCVTAS_32S_FLOAT2INT) = FCVTAS_F32_S32;
DEF_ISEL(FCVTAS_64S_FLOAT2INT) = FCVTAS_F32_S64;
DEF_ISEL(FCVTAS_32D_FLOAT2INT) = FCVTAS_F64_S32;
DEF_ISEL(FCVTAS_64D_FLOAT2INT) = FCVTAS_F64_S64;
// FCVTAU — round Away → unsigned
DEF_ISEL(FCVTAU_32S_FLOAT2INT) = FCVTAS_F32_U32;
DEF_ISEL(FCVTAU_64S_FLOAT2INT) = FCVTAS_F32_U64;
DEF_ISEL(FCVTAU_32D_FLOAT2INT) = FCVTAS_F64_U32;
DEF_ISEL(FCVTAU_64D_FLOAT2INT) = FCVTAS_F64_U64;
// FCVTNS — round to Nearest → signed
DEF_ISEL(FCVTNS_32S_FLOAT2INT) = FCVTNS_F32_S32;
DEF_ISEL(FCVTNS_64S_FLOAT2INT) = FCVTNS_F32_S64;
DEF_ISEL(FCVTNS_32D_FLOAT2INT) = FCVTNS_F64_S32;
DEF_ISEL(FCVTNS_64D_FLOAT2INT) = FCVTNS_F64_S64;
// FCVTNU — round to Nearest → unsigned
DEF_ISEL(FCVTNU_32S_FLOAT2INT) = FCVTNS_F32_U32;
DEF_ISEL(FCVTNU_64S_FLOAT2INT) = FCVTNS_F32_U64;
DEF_ISEL(FCVTNU_32D_FLOAT2INT) = FCVTNS_F64_U32;
DEF_ISEL(FCVTNU_64D_FLOAT2INT) = FCVTNS_F64_U64;
// FCVTPS — round to +Inf → signed
DEF_ISEL(FCVTPS_32S_FLOAT2INT) = FCVTPS_F32_S32;
DEF_ISEL(FCVTPS_64S_FLOAT2INT) = FCVTPS_F32_S64;
DEF_ISEL(FCVTPS_32D_FLOAT2INT) = FCVTPS_F64_S32;
DEF_ISEL(FCVTPS_64D_FLOAT2INT) = FCVTPS_F64_S64;
// FCVTPU — round to +Inf → unsigned
DEF_ISEL(FCVTPU_32S_FLOAT2INT) = FCVTPS_F32_U32;
DEF_ISEL(FCVTPU_64S_FLOAT2INT) = FCVTPS_F32_U64;
DEF_ISEL(FCVTPU_32D_FLOAT2INT) = FCVTPS_F64_U32;
DEF_ISEL(FCVTPU_64D_FLOAT2INT) = FCVTPS_F64_U64;
// FCVTMS — round to -Inf → signed
DEF_ISEL(FCVTMS_32S_FLOAT2INT) = FCVTMS_F32_S32;
DEF_ISEL(FCVTMS_64S_FLOAT2INT) = FCVTMS_F32_S64;
DEF_ISEL(FCVTMS_32D_FLOAT2INT) = FCVTMS_F64_S32;
DEF_ISEL(FCVTMS_64D_FLOAT2INT) = FCVTMS_F64_S64;
// FCVTMU — round to -Inf → unsigned
DEF_ISEL(FCVTMU_32S_FLOAT2INT) = FCVTMS_F32_U32;
DEF_ISEL(FCVTMU_64S_FLOAT2INT) = FCVTMS_F32_U64;
DEF_ISEL(FCVTMU_32D_FLOAT2INT) = FCVTMS_F64_U32;
DEF_ISEL(FCVTMU_64D_FLOAT2INT) = FCVTMS_F64_U64;

DEF_ISEL(FCVT_DS_FLOATDP1) = FCVT_Float32ToFloat64;
DEF_ISEL(FCVT_SD_FLOATDP1) = FCVT_Float64ToFloat32;

namespace {

DEF_SEM(SCVTF_Int32ToFloat32, V128W dst, R32 src) {
  auto res = CheckedCast<int32_t, float32_t>(state, Signed(Read(src)));
  FWriteV32(dst, res);
  return memory;
}

DEF_SEM(SCVTF_Int32ToFloat64, V128W dst, R32 src) {
  auto res = CheckedCast<int32_t, float64_t>(state, Signed(Read(src)));
  FWriteV64(dst, res);
  return memory;
}

DEF_SEM(SCVTF_Int64ToFloat32, V128W dst, R64 src) {
  auto res = CheckedCast<int64_t, float32_t>(state, Signed(Read(src)));
  FWriteV32(dst, res);
  return memory;
}

DEF_SEM(SCVTF_Int64ToFloat64, V128W dst, R64 src) {
  auto res = CheckedCast<int64_t, float64_t>(state, Signed(Read(src)));
  FWriteV64(dst, res);
  return memory;
}

}  // namespace

// TODO(pag): SCVTF_H32_FLOAT2INT.
// TODO(pag): SCVTF_H64_FLOAT2INT.

DEF_ISEL(SCVTF_S32_FLOAT2INT) = SCVTF_Int32ToFloat32;
DEF_ISEL(SCVTF_D32_FLOAT2INT) = SCVTF_Int32ToFloat64;
DEF_ISEL(SCVTF_S64_FLOAT2INT) = SCVTF_Int64ToFloat32;
DEF_ISEL(SCVTF_D64_FLOAT2INT) = SCVTF_Int64ToFloat64;
