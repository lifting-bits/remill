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
  Write(dst, src);
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
  Write(dst, src);
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

namespace {
// Offset
DEF_COND_SEM(STRH, M16W dst, R32 src1) {
  auto src = Read(src1);
  Write(dst, TruncTo<uint16_t>(src));
  return memory;
}

// Pre + Post
DEF_COND_SEM(STRHp, M16W dst, R32 src1, R32W dst_reg, R32 src2) {
  auto src = Read(src1);
  auto new_val = Read(src2);
  Write(dst, TruncTo<uint16_t>(src));
  Write(dst_reg, new_val);
  return memory;
}

// Offset
DEF_COND_SEM(LDRH, M16 src1, R32W dst) {
  auto src = Read(src1);
  WriteZExt(dst, src);
  return memory;
}

// Pre + Post
DEF_COND_SEM(LDRHp, M16 src1, R32W dst, R32W dst_reg, R32 src2) {
  auto src = Read(src1);
  auto new_val = Read(src2);
  WriteZExt(dst, src);
  Write(dst_reg, new_val);
  return memory;
}

// Offset
DEF_COND_SEM(STRD, M64W dst, R32 src1, R32 src2) {
  auto lhs = UShl(ZExt<uint64_t>(Read(src2)), 32ul);
  auto rhs = ZExt<uint64_t>(Read(src1));
  auto src = UOr(lhs, rhs);
  WriteTrunc(dst, src);
  return memory;
}

// Pre + Post
DEF_COND_SEM(STRDp, M64W dst, R32 src1, R32 src2, R32W dst_reg, R32 src_new) {
  auto lhs = UShl(ZExt<uint64_t>(Read(src2)), 32ul);
  auto rhs = ZExt<uint64_t>(Read(src1));
  auto src = UOr(lhs, rhs);
  auto new_val = Read(src_new);
  WriteTrunc(dst, src);
  Write(dst_reg, new_val);
  return memory;
}

// Offset
DEF_COND_SEM(LDRD, M64 src1, R32W dst1, R32W dst2) {
  auto src = Read(src1);
  Write(dst1, TruncTo<uint32_t>(src));
  Write(dst2, TruncTo<uint32_t>(UShr(src, 32ul)));
  return memory;
}

// Pre + Post
DEF_COND_SEM(LDRDp, M64 src1, R32W dst1, R32W dst2, R32W dst_reg, R32 src2) {
  auto src = Read(src1);
  auto new_val = Read(src2);
  Write(dst1, TruncTo<uint32_t>(src));
  Write(dst2, TruncTo<uint32_t>(UShr(src, 32ul)));
  Write(dst_reg, new_val);
  return memory;
}

// Offset
DEF_COND_SEM(LDRSB, M8 src1, R32W dst) {
  auto src = Read(src1);
  WriteSExt(dst, src);
  return memory;
}

// Pre + Post
DEF_COND_SEM(LDRSBp, M8 src1, R32W dst, R32W dst_reg, R32 src2) {
  auto src = Read(src1);
  auto new_val = Read(src2);
  WriteSExt(dst, src);
  Write(dst_reg, new_val);
  return memory;
}

// Offset
DEF_COND_SEM(LDRSH, M16 src1, R32W dst) {
  auto src = Read(src1);
  WriteSExt(dst, src);
  return memory;
}

// Pre + Post
DEF_COND_SEM(LDRSHp, M16 src1, R32W dst, R32W dst_reg, R32 src2) {
  auto src = Read(src1);
  auto new_val = Read(src2);
  WriteSExt(dst, src);
  Write(dst_reg, new_val);
  return memory;
}

DEF_COND_SEM(STRHT, M16W dst, R32 src1, R32W dst_reg, R32 src2) {
  memory = __remill_sync_hyper_call(state, memory, SyncHyperCall::kAArch32CheckNotEL2);
  auto src = Read(src1);
  auto new_val = Read(src2);
  WriteTrunc(dst, src);
  Write(dst_reg, new_val);
  return memory;
}

DEF_COND_SEM(LDRHT, M16 src1, R32W dst, R32W dst_reg, R32 src2) {
  memory = __remill_sync_hyper_call(state, memory, SyncHyperCall::kAArch32CheckNotEL2);
  auto src = Read(src1);
  auto new_val = Read(src2);
  WriteZExt(dst, src);
  Write(dst_reg, new_val);
  return memory;
}

DEF_COND_SEM(LDRSBT, M8 src1, R32W dst, R32W dst_reg, R32 src2) {
  memory = __remill_sync_hyper_call(state, memory, SyncHyperCall::kAArch32CheckNotEL2);
  auto src = Read(src1);
  auto new_val = Read(src2);
  WriteSExt(dst, src);
  Write(dst_reg, new_val);
  return memory;
}

DEF_COND_SEM(LDRSHT, M16 src1, R32W dst, R32W dst_reg, R32 src2) {
  memory = __remill_sync_hyper_call(state, memory, SyncHyperCall::kAArch32CheckNotEL2);
  auto src = Read(src1);
  auto new_val = Read(src2);
  WriteSExt(dst, src);
  Write(dst_reg, new_val);
  return memory;
}

} // namespace

DEF_ISEL(STRH) = STRH;
DEF_ISEL(STRHp) = STRHp;
DEF_ISEL(LDRH) = LDRH;
DEF_ISEL(LDRHp) = LDRHp;
DEF_ISEL(STRD) = STRD;
DEF_ISEL(STRDp) = STRDp;
DEF_ISEL(LDRD) = LDRD;
DEF_ISEL(LDRDp) = LDRDp;
DEF_ISEL(LDRSB) = LDRSB;
DEF_ISEL(LDRSBp) = LDRSBp;
DEF_ISEL(LDRSH) = LDRSH;
DEF_ISEL(LDRSHp) = LDRSHp;
DEF_ISEL(STRHT) = STRHT;
DEF_ISEL(LDRHT) = LDRHT;
DEF_ISEL(LDRSBT) = LDRSBT;
DEF_ISEL(LDRSHT) = LDRSHT;
