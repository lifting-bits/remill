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
DEF_COND_SEM(STR, M32W dst, R32 src1) {
  auto src = Read(src1);
  Write(dst, TruncTo<uint32_t>(src));
  return memory;
}

DEF_COND_SEM(STRB, M8W dst, R32 src1) {
  auto src = Read(src1);
  Write(dst, TruncTo<uint8_t>(src));
  return memory;
}

// Pre + Post
DEF_COND_SEM(STRp, M32W dst, R32 src1, R32W dst_reg, R32 src2) {
  auto src = Read(src1);
  auto new_val = Read(src2);
  Write(dst, TruncTo<uint32_t>(src));
  Write(dst_reg, new_val);
  return memory;
}

// Pre + Post
DEF_COND_SEM(STRBp, M8W dst, R32 src1, R32W dst_reg, R32 src2) {
  auto src = Read(src1);
  auto new_val = Read(src2);
  Write(dst, TruncTo<uint8_t>(src));
  Write(dst_reg, new_val);
  return memory;
}

// Offset
DEF_COND_SEM(LDR, M32 src1, R32W dst) {
  auto src = Read(src1);
  WriteZExt(dst, src);
  return memory;
}

// Offset
DEF_COND_SEM(LDRB, M8 src1, R32W dst) {
  auto src = Read(src1);
  WriteZExt(dst, src);
  return memory;
}

// Pre + Post
DEF_COND_SEM(LDRp, M32 src1, R32W dst, R32W dst_reg, R32 src2) {
  auto src = Read(src1);
  auto new_val = Read(src2);
  WriteZExt(dst, src);
  Write(dst_reg, new_val);
  return memory;
}

// Pre + Post
DEF_COND_SEM(LDRBp, M8 src1, R32W dst, R32W dst_reg, R32 src2) {
  auto src = Read(src1);
  auto new_val = Read(src2);
  WriteZExt(dst, src);
  Write(dst_reg, new_val);
  return memory;
}

DEF_COND_SEM(STRT, M32W dst, R32 src1, R32W dst_reg, R32 src2) {
  memory = __remill_sync_hyper_call(state, memory, SyncHyperCall::kAArch32CheckNotEL2);
  auto src = Read(src1);
  auto new_val = Read(src2);
  Write(dst, TruncTo<uint32_t>(src));
  Write(dst_reg, new_val);
  return memory;
}

DEF_COND_SEM(STRTB, M8W dst, R32 src1, R32W dst_reg, R32 src2) {
  memory = __remill_sync_hyper_call(state, memory, SyncHyperCall::kAArch32CheckNotEL2);
  auto src = Read(src1);
  auto new_val = Read(src2);
  Write(dst, TruncTo<uint8_t>(src));
  Write(dst_reg, new_val);
  return memory;
}

DEF_COND_SEM(LDRT, M32 src1, R32W dst, R32W dst_reg, R32 src2) {
  memory = __remill_sync_hyper_call(state, memory, SyncHyperCall::kAArch32CheckNotEL2);
  auto src = Read(src1);
  auto new_val = Read(src2);
  WriteZExt(dst, src);
  Write(dst_reg, new_val);
  return memory;
}

DEF_COND_SEM(LDRTB, M8 src1, R32W dst, R32W dst_reg, R32 src2) {
  memory = __remill_sync_hyper_call(state, memory, SyncHyperCall::kAArch32CheckNotEL2);
  auto src = Read(src1);
  auto new_val = Read(src2);
  WriteZExt(dst, src);
  Write(dst_reg, new_val);
  return memory;
}

} // namespace

DEF_ISEL(STR) = STR;
DEF_ISEL(STRB) = STRB;
DEF_ISEL(STRp) = STRp;
DEF_ISEL(STRBp) = STRBp;
DEF_ISEL(LDR) = LDR;
DEF_ISEL(LDRB) = LDRB;
DEF_ISEL(LDRp) = LDRp;
DEF_ISEL(LDRBp) = LDRBp;
DEF_ISEL(STRT) = STRT;
DEF_ISEL(STRBT) = STRTB;
DEF_ISEL(LDRT) = LDRT;
DEF_ISEL(LDRBT) = LDRTB;
