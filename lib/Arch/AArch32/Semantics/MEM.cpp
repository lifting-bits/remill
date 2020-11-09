/*
 * Copyright (c) 2020 Trail of Bits, Inc.
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
// Offset
template<typename DstType, typename ValType>
DEF_SEM(STR, DstType dst, R32 src1) {
  auto src = Read(src1);
  Write(dst, TruncTo<ValType>(src));
  return memory;
}

// Pre + Post
template<typename DstType, typename ValType>
DEF_SEM(STRp, DstType dst, R32 src1, R32W dst_reg, R32 src2) {
  auto src = Read(src1);
  auto new_val = Read(src2);
  Write(dst, TruncTo<ValType>(src));
  Write(dst_reg, new_val);
  return memory;
}

// Offset
template<typename SrcType>
DEF_SEM(LDR, SrcType src1, R32W dst) {
  auto src = Read(src1);
  WriteZExt(dst, src);
  return memory;
}

// Pre + Post
template<typename SrcType>
DEF_SEM(LDRp, SrcType src1, R32W dst, R32W dst_reg, R32 src2) {
  auto src = Read(src1);
  auto new_val = Read(src2);
  WriteZExt(dst, src);
  Write(dst_reg, new_val);
  return memory;
}

template<typename DstType, typename ValType>
DEF_SEM(STRT, DstType dst, R32 src1, R32W dst_reg, R32 src2) {
  memory = __remill_sync_hyper_call(state, memory, SyncHyperCall::kAArch32CheckNotEL2);
  auto src = Read(src1);
  auto new_val = Read(src2);
  Write(dst, TruncTo<ValType>(src));
  Write(dst_reg, new_val);
  return memory;
}

template<typename SrcType>
DEF_SEM(LDRT, SrcType src1, R32W dst, R32W dst_reg, R32 src2) {
  memory = __remill_sync_hyper_call(state, memory, SyncHyperCall::kAArch32CheckNotEL2);
  auto src = Read(src1);
  auto new_val = Read(src2);
  WriteZExt(dst, src);
  Write(dst_reg, new_val);
  return memory;
}

} // namespace

DEF_ISEL(STR) = STR<M32W, uint32_t>;
DEF_ISEL(STRB) = STR<M8W, uint8_t>;
DEF_ISEL(STRp) = STRp<M32W, uint32_t>;
DEF_ISEL(STRBp) = STRp<M8W, uint8_t>;
DEF_ISEL(LDR) = LDR<M32>;
DEF_ISEL(LDRB) = LDR<M8>;
DEF_ISEL(LDRp) = LDRp<M32>;
DEF_ISEL(LDRBp) = LDRp<M8>;
DEF_ISEL(STRT) = STRT<M32W, uint32_t>;
DEF_ISEL(STRBT) = STRT<M8W, uint8_t>;
DEF_ISEL(LDRT) = LDRT<M32>;
DEF_ISEL(LDRBT) = LDRT<M8>;
