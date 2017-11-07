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
ALWAYS_INLINE static D FPConvertIntToFloat(State &state, S src) {
  auto res = static_cast<D>(src);

  if (std::isinf(res)) {
    state.sr.ofc = true;  // Overflow.
    state.sr.ixc = true;  // Inexact.

  } else if (static_cast<S>(res) != src) {
    state.sr.ixc = true;  // Inexact.
  }
  // Can't underflow, because we're converting an integer to a float.
  return res;
}

template <typename S, typename D>
D FPConvertFloatTo(State &state, S src) {
  // std::feclearexcept(FE_ALL_EXCEPT);
  auto res = static_cast<D>(src);
  // Handle extra rounding errors (ignore INEXACT on NaN)
  SetFPSRStatusFlags(state, src);
  // if (!std::isnan(src)) {
  //   state.sr.ixc = (reinterpret_cast<S &>(res) != src);
  // }

  // if(src == 0 && std::signbit(src)) {
  //   state.sr.ixc = true;
  // }
  // If src was negative 0, this is also inexact conversion

  // Check for FE underflow
  // state.sr.ufc = /*(std::isinf(res) && res < 0) ||*/ (src != 0 && res == 0);

  return res;
}

DEF_SEM(UCVTF_UInt32ToFloat32, V128W dst, R32 src) {
  auto res = FPConvertIntToFloat<uint32_t, float32_t>(state, Read(src));
  FWriteV32(dst, res);
  return memory;
}

DEF_SEM(UCVTF_UInt32ToFloat64, V128W dst, R32 src) {
  auto res = FPConvertIntToFloat<uint32_t, float64_t>(state, Read(src));
  FWriteV64(dst, res);
  return memory;
}

DEF_SEM(UCVTF_UInt64ToFloat32, V128W dst, R64 src) {
  auto res = FPConvertIntToFloat<uint64_t, float32_t>(state, Read(src));
  FWriteV32(dst, res);
  return memory;
}

DEF_SEM(UCVTF_UInt64ToFloat64, V128W dst, R64 src) {
  auto res = FPConvertIntToFloat<uint64_t, float64_t>(state, Read(src));
  FWriteV64(dst, res);
  return memory;
}

DEF_SEM(FCVTZU_Float32ToUInt32, R32W dst, V32 src) {
  auto float_val = FExtractV32(FReadV32(src), 0);
  auto res = FPConvertFloatTo<float32_t, uint32_t>(state, float_val);
  WriteZExt(dst, res);
  return memory;
}

DEF_SEM(FCVTZU_Float32ToUInt64, R64W dst, V32 src) {
  auto float_val = FExtractV32(FReadV32(src), 0);
  auto res = FPConvertFloatTo<float32_t, uint64_t>(state, float_val);
  WriteZExt(dst, res);
  return memory;
}

DEF_SEM(FCVTZU_Float64ToUInt32, R32W dst, V64 src) {
  auto float_val = FExtractV64(FReadV64(src), 0);
  auto res = FPConvertFloatTo<float64_t, uint32_t>(state, float_val);
  WriteZExt(dst, res);
  return memory;
}

DEF_SEM(FCVTZU_Float64ToUInt64, R64W dst, V64 src) {
  auto float_val = FExtractV64(FReadV64(src), 0);
  auto res = FPConvertFloatTo<float64_t, uint64_t>(state, float_val);
  WriteZExt(dst, res);
  return memory;
}

DEF_SEM(FCVTZS_Float64ToSInt32, R32W dst, V64 src) {
  auto float_val = FExtractV64(FReadV64(src), 0);
  auto res = FPConvertFloatTo<float64_t, int32_t>(state, float_val);
  WriteZExt(dst, res);
  return memory;
}

DEF_SEM(FCVTZS_Float64ToSInt64, R64W dst, V64 src) {
  auto float_val = FExtractV64(FReadV64(src), 0);
  auto res = FPConvertFloatTo<float64_t, int64_t>(state, float_val);
  WriteZExt(dst, res);
  return memory;
}

DEF_SEM(FCVT_Float32ToFloat64, V128W dst, V32 src) {
  auto float_val = FExtractV32(FReadV32(src), 0);
  auto res = FPConvertFloatTo<float32_t, float64_t>(state, float_val);
  FWriteV64(dst, res);
  return memory;
}

DEF_SEM(FCVT_Float64ToFloat32, V128W dst, V64 src) {
  auto float_val = FExtractV64(FReadV64(src), 0);
  auto res = FPConvertFloatTo<float64_t, float32_t>(state, float_val);
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

DEF_ISEL(FCVTZS_32D_FLOAT2INT) = FCVTZS_Float64ToSInt32;
DEF_ISEL(FCVTZS_64D_FLOAT2INT) = FCVTZS_Float64ToSInt64;

DEF_ISEL(FCVT_DS_FLOATDP1) = FCVT_Float32ToFloat64;
DEF_ISEL(FCVT_SD_FLOATDP1) = FCVT_Float64ToFloat32;

namespace {

DEF_SEM(SCVTF_Int32ToFloat32, V128W dst, R32 src) {
  auto res = FPConvertIntToFloat<int32_t, float32_t>(state, Signed(Read(src)));
  FWriteV32(dst, res);
  return memory;
}

DEF_SEM(SCVTF_Int32ToFloat64, V128W dst, R32 src) {
  auto res = FPConvertIntToFloat<int32_t, float64_t>(state, Signed(Read(src)));
  FWriteV64(dst, res);
  return memory;
}

DEF_SEM(SCVTF_Int64ToFloat32, V128W dst, R64 src) {
  auto res = FPConvertIntToFloat<int64_t, float32_t>(state, Signed(Read(src)));
  FWriteV32(dst, res);
  return memory;
}

DEF_SEM(SCVTF_Int64ToFloat64, V128W dst, R64 src) {
  auto res = FPConvertIntToFloat<int64_t, float64_t>(state, Signed(Read(src)));
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
