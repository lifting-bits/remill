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

DEF_SEM(UCVTF_UInt32ToFloat32, V128W dst, R32 src) {
  FWriteV32(dst, Float32(Read(src)));
  return memory;
}

DEF_SEM(UCVTF_UInt32ToFloat64, V128W dst, R32 src) {
  FWriteV64(dst, Float64(Read(src)));
  return memory;
}

DEF_SEM(UCVTF_UInt64ToFloat32, V128W dst, R64 src) {
  FWriteV32(dst, Float32(Read(src)));
  return memory;
}

DEF_SEM(UCVTF_UInt64ToFloat64, V128W dst, R64 src) {
  FWriteV64(dst, Float64(Read(src)));
  return memory;
}

}  // namespace

// TODO(pag): UCVTF_H32_FLOAT2INT.
// TODO(pag): UCVTF_H64_FLOAT2INT.

DEF_ISEL(UCVTF_S32_FLOAT2INT) = UCVTF_UInt32ToFloat32;
DEF_ISEL(UCVTF_D32_FLOAT2INT) = UCVTF_UInt32ToFloat64;

DEF_ISEL(UCVTF_S64_FLOAT2INT) = UCVTF_UInt64ToFloat32;
DEF_ISEL(UCVTF_D64_FLOAT2INT) = UCVTF_UInt64ToFloat64;
