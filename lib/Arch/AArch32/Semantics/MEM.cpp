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
DEF_COND_SEM(STR, M32W dst, R32 src1, R32W maybe_next_pc_dst) {
  auto src = Read(src1);
  Write(dst, src);

  // ignore maybe_next_pc_dst since the semantic does not
  // update program counter
  (void) maybe_next_pc_dst;
  return memory;
}

DEF_COND_SEM(STRB, M8W dst, R32 src1, R32W maybe_next_pc_dst) {
  auto src = Read(src1);
  Write(dst, TruncTo<uint8_t>(src));

  // ignore maybe_next_pc_dst since the semantic does not
  // update program counter
  (void) maybe_next_pc_dst;
  return memory;
}

// Pre + Post
DEF_COND_SEM(STRp, M32W dst, R32 src1, R32W dst_reg, R32 src2,
             R32W maybe_next_pc_dst) {
  auto src = Read(src1);
  auto new_val = Read(src2);
  Write(dst, src);
  Write(dst_reg, new_val);

  // update maybe_next_pc_dst with the PC; It may get ignored
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

// Pre + Post
DEF_COND_SEM(STRBp, M8W dst, R32 src1, R32W dst_reg, R32 src2,
             R32W maybe_next_pc_dst) {
  auto src = Read(src1);
  auto new_val = Read(src2);
  Write(dst, TruncTo<uint8_t>(src));
  Write(dst_reg, new_val);

  // update maybe_next_pc_dst with the PC; It may get ignored
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

// Offset
DEF_COND_SEM(LDR, M32 src1, R32W dst, R32W maybe_next_pc_dst) {
  auto src = Read(src1);
  WriteZExt(dst, src);

  // update maybe_next_pc_dst with the PC;
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

// Offset
DEF_COND_SEM(LDRB, M8 src1, R32W dst, R32W maybe_next_pc_dst) {
  auto src = Read(src1);
  WriteZExt(dst, src);

  // update maybe_next_pc_dst with the PC;
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

// Pre + Post
DEF_COND_SEM(LDRp, M32 src1, R32W dst, R32W dst_reg, R32 src2,
             R32W maybe_next_pc_dst) {
  auto src = Read(src1);
  auto new_val = Read(src2);
  WriteZExt(dst, src);
  Write(dst_reg, new_val);

  // update maybe_next_pc_dst with the PC;
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

// Pre + Post
DEF_COND_SEM(LDRBp, M8 src1, R32W dst, R32W dst_reg, R32 src2,
             R32W maybe_next_pc_dst) {
  auto src = Read(src1);
  auto new_val = Read(src2);
  WriteZExt(dst, src);
  Write(dst_reg, new_val);

  // update maybe_next_pc_dst with the PC;
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(STRT, M32W dst, R32 src1, R32W dst_reg, R32 src2,
             R32W maybe_next_pc_dst) {
  memory = __remill_sync_hyper_call(state, memory,
                                    SyncHyperCall::kAArch32CheckNotEL2);
  auto src = Read(src1);
  auto new_val = Read(src2);
  Write(dst, TruncTo<uint32_t>(src));
  Write(dst_reg, new_val);

  // update maybe_next_pc_dst with the PC;
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(STRTB, M8W dst, R32 src1, R32W dst_reg, R32 src2,
             R32W maybe_next_pc_dst) {
  memory = __remill_sync_hyper_call(state, memory,
                                    SyncHyperCall::kAArch32CheckNotEL2);
  auto src = Read(src1);
  auto new_val = Read(src2);
  Write(dst, TruncTo<uint8_t>(src));
  Write(dst_reg, new_val);

  // update maybe_next_pc_dst with the PC;
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(LDRT, M32 src1, R32W dst, R32W dst_reg, R32 src2,
             R32W maybe_next_pc_dst) {
  memory = __remill_sync_hyper_call(state, memory,
                                    SyncHyperCall::kAArch32CheckNotEL2);
  auto src = Read(src1);
  auto new_val = Read(src2);
  WriteZExt(dst, src);
  Write(dst_reg, new_val);

  // update maybe_next_pc_dst with the PC;
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(LDRTB, M8 src1, R32W dst, R32W dst_reg, R32 src2,
             R32W maybe_next_pc_dst) {
  memory = __remill_sync_hyper_call(state, memory,
                                    SyncHyperCall::kAArch32CheckNotEL2);
  auto src = Read(src1);
  auto new_val = Read(src2);
  WriteZExt(dst, src);
  Write(dst_reg, new_val);
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

}  // namespace

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
DEF_COND_SEM(STRH, M16W dst, R32 src1, R32W maybe_next_pc_dst) {
  auto src = Read(src1);
  Write(dst, TruncTo<uint16_t>(src));

  // ignore maybe_next_pc_dst
  (void) maybe_next_pc_dst;
  return memory;
}

// Pre + Post
DEF_COND_SEM(STRHp, M16W dst, R32 src1, R32W dst_reg, R32 src2,
             R32W maybe_next_pc_dst) {
  auto src = Read(src1);
  auto new_val = Read(src2);
  Write(dst, TruncTo<uint16_t>(src));
  Write(dst_reg, new_val);

  // ignore maybe_next_pc_dst
  (void) maybe_next_pc_dst;
  return memory;
}

// Offset
DEF_COND_SEM(LDRH, M16 src1, R32W dst, R32W maybe_next_pc_dst) {
  auto src = Read(src1);
  WriteZExt(dst, src);
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

// Pre + Post
DEF_COND_SEM(LDRHp, M16 src1, R32W dst, R32W dst_reg, R32 src2,
             R32W maybe_next_pc_dst) {
  auto src = Read(src1);
  auto new_val = Read(src2);
  WriteZExt(dst, src);
  Write(dst_reg, new_val);
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

// Offset
DEF_COND_SEM(STRD, M64W dst, R32 src1, R32 src2, R32W maybe_next_pc_dst) {
  auto lhs = UShl(ZExt<uint64_t>(Read(src2)), 32ul);
  auto rhs = ZExt<uint64_t>(Read(src1));
  auto src = UOr(lhs, rhs);
  WriteTrunc(dst, src);
  return memory;
}

// Pre + Post
DEF_COND_SEM(STRDp, M64W dst, R32 src1, R32 src2, R32W dst_reg, R32 src_new,
             R32W maybe_next_pc_dst) {
  auto lhs = UShl(ZExt<uint64_t>(Read(src2)), 32ul);
  auto rhs = ZExt<uint64_t>(Read(src1));
  auto src = UOr(lhs, rhs);
  auto new_val = Read(src_new);
  WriteTrunc(dst, src);
  Write(dst_reg, new_val);
  return memory;
}

// Offset
DEF_COND_SEM(LDRD, M64 src1, R32W dst1, R32W dst2, R32W maybe_next_pc_dst) {
  auto src = Read(src1);
  Write(dst1, TruncTo<uint32_t>(src));
  Write(dst2, TruncTo<uint32_t>(UShr(src, 32ul)));
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

// Pre + Post
DEF_COND_SEM(LDRDp, M64 src1, R32W dst1, R32W dst2, R32W dst_reg, R32 src2,
             R32W maybe_next_pc_dst) {
  auto src = Read(src1);
  auto new_val = Read(src2);
  Write(dst1, TruncTo<uint32_t>(src));
  Write(dst2, TruncTo<uint32_t>(UShr(src, 32ul)));
  Write(dst_reg, new_val);
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

// Offset
DEF_COND_SEM(LDRSB, M8 src1, R32W dst, R32W maybe_next_pc_dst) {
  auto src = Read(src1);
  WriteSExt(dst, src);
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

// Pre + Post
DEF_COND_SEM(LDRSBp, M8 src1, R32W dst, R32W dst_reg, R32 src2,
             R32W maybe_next_pc_dst) {
  auto src = Read(src1);
  auto new_val = Read(src2);
  WriteSExt(dst, src);
  Write(dst_reg, new_val);
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

// Offset
DEF_COND_SEM(LDRSH, M16 src1, R32W dst, R32W maybe_next_pc_dst) {
  auto src = Read(src1);
  WriteSExt(dst, src);
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

// Pre + Post
DEF_COND_SEM(LDRSHp, M16 src1, R32W dst, R32W dst_reg, R32 src2,
             R32W maybe_next_pc_dst) {
  auto src = Read(src1);
  auto new_val = Read(src2);
  WriteSExt(dst, src);
  Write(dst_reg, new_val);
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(STRHT, M16W dst, R32 src1, R32W dst_reg, R32 src2,
             R32W maybe_next_pc_dst) {
  memory = __remill_sync_hyper_call(state, memory,
                                    SyncHyperCall::kAArch32CheckNotEL2);
  auto src = Read(src1);
  auto new_val = Read(src2);
  WriteTrunc(dst, src);
  Write(dst_reg, new_val);
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(LDRHT, M16 src1, R32W dst, R32W dst_reg, R32 src2,
             R32W maybe_next_pc_dst) {
  memory = __remill_sync_hyper_call(state, memory,
                                    SyncHyperCall::kAArch32CheckNotEL2);
  auto src = Read(src1);
  auto new_val = Read(src2);
  WriteZExt(dst, src);
  Write(dst_reg, new_val);
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(LDRSBT, M8 src1, R32W dst, R32W dst_reg, R32 src2,
             R32W maybe_next_pc_dst) {
  memory = __remill_sync_hyper_call(state, memory,
                                    SyncHyperCall::kAArch32CheckNotEL2);
  auto src = Read(src1);
  auto new_val = Read(src2);
  WriteSExt(dst, src);
  Write(dst_reg, new_val);
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(LDRSHT, M16 src1, R32W dst, R32W dst_reg, R32 src2,
             R32W maybe_next_pc_dst) {
  memory = __remill_sync_hyper_call(state, memory,
                                    SyncHyperCall::kAArch32CheckNotEL2);
  auto src = Read(src1);
  auto new_val = Read(src2);
  WriteSExt(dst, src);
  Write(dst_reg, new_val);
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

}  // namespace

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

// Load/Store Multiple
namespace {
DEF_COND_SEM(LDM, I16 reg_list, R32W dst, R32 dst_new, M32 src_mem, R32W dst0,
             R32W dst1, R32W dst2, R32W dst3, R32W dst4, R32W dst5, R32W dst6,
             R32W dst7, R32W dst8, R32W dst9, R32W dst10, R32W dst11,
             R32W dst12, R32W dst13, R32W dst14, R32W dst15,
             R32W maybe_next_pc_dst) {
  auto regs = Read(reg_list);
  uint32_t index = 0;
  if (UAnd(regs, uint16_t(0b1u))) {
    Write(dst0, Read(GetElementPtr(src_mem, index++)));
  }
  if (UAnd(regs, uint16_t(0b1u << 1))) {
    Write(dst1, Read(GetElementPtr(src_mem, index++)));
  }
  if (UAnd(regs, uint16_t(0b1u << 2))) {
    Write(dst2, Read(GetElementPtr(src_mem, index++)));
  }
  if (UAnd(regs, uint16_t(0b1u << 3))) {
    Write(dst3, Read(GetElementPtr(src_mem, index++)));
  }
  if (UAnd(regs, uint16_t(0b1u << 4))) {
    Write(dst4, Read(GetElementPtr(src_mem, index++)));
  }
  if (UAnd(regs, uint16_t(0b1u << 5))) {
    Write(dst5, Read(GetElementPtr(src_mem, index++)));
  }
  if (UAnd(regs, uint16_t(0b1u << 6))) {
    Write(dst6, Read(GetElementPtr(src_mem, index++)));
  }
  if (UAnd(regs, uint16_t(0b1u << 7))) {
    Write(dst7, Read(GetElementPtr(src_mem, index++)));
  }
  if (UAnd(regs, uint16_t(0b1u << 8))) {
    Write(dst8, Read(GetElementPtr(src_mem, index++)));
  }
  if (UAnd(regs, uint16_t(0b1u << 9))) {
    Write(dst9, Read(GetElementPtr(src_mem, index++)));
  }
  if (UAnd(regs, uint16_t(0b1u << 10))) {
    Write(dst10, Read(GetElementPtr(src_mem, index++)));
  }
  if (UAnd(regs, uint16_t(0b1u << 11))) {
    Write(dst11, Read(GetElementPtr(src_mem, index++)));
  }
  if (UAnd(regs, uint16_t(0b1u << 12))) {
    Write(dst12, Read(GetElementPtr(src_mem, index++)));
  }
  if (UAnd(regs, uint16_t(0b1u << 13))) {
    Write(dst13, Read(GetElementPtr(src_mem, index++)));
  }
  if (UAnd(regs, uint16_t(0b1u << 14))) {
    Write(dst14, Read(GetElementPtr(src_mem, index++)));
  }
  if (UAnd(regs, uint16_t(0b1u << 15))) {
    Write(dst15, Read(GetElementPtr(src_mem, index++)));
  }
  Write(dst, Read(dst_new));
  Write(maybe_next_pc_dst, Read(REG_PC));
  return memory;
}

DEF_COND_SEM(STMDB, I16 reg_list, R32W dst, R32 dst_new, M32W dst_mem, R32 src0,
             R32 src1, R32 src2, R32 src3, R32 src4, R32 src5, R32 src6,
             R32 src7, R32 src8, R32 src9, R32 src10, R32 src11, R32 src12,
             R32 src13, R32 src14, R32 src15, R32W maybe_next_pc_dst) {
  auto regs = Read(reg_list);
  uint32_t index = 0;
  if (UAnd(regs, uint16_t(0b1u))) {
    Write(GetElementPtr(dst_mem, index++), Read(src0));
  }
  if (UAnd(regs, uint16_t(0b1u << 1))) {
    Write(GetElementPtr(dst_mem, index++), Read(src1));
  }
  if (UAnd(regs, uint16_t(0b1u << 2))) {
    Write(GetElementPtr(dst_mem, index++), Read(src2));
  }
  if (UAnd(regs, uint16_t(0b1u << 3))) {
    Write(GetElementPtr(dst_mem, index++), Read(src3));
  }
  if (UAnd(regs, uint16_t(0b1u << 4))) {
    Write(GetElementPtr(dst_mem, index++), Read(src4));
  }
  if (UAnd(regs, uint16_t(0b1u << 5))) {
    Write(GetElementPtr(dst_mem, index++), Read(src5));
  }
  if (UAnd(regs, uint16_t(0b1u << 6))) {
    Write(GetElementPtr(dst_mem, index++), Read(src6));
  }
  if (UAnd(regs, uint16_t(0b1u << 7))) {
    Write(GetElementPtr(dst_mem, index++), Read(src7));
  }
  if (UAnd(regs, uint16_t(0b1u << 8))) {
    Write(GetElementPtr(dst_mem, index++), Read(src8));
  }
  if (UAnd(regs, uint16_t(0b1u << 9))) {
    Write(GetElementPtr(dst_mem, index++), Read(src9));
  }
  if (UAnd(regs, uint16_t(0b1u << 10))) {
    Write(GetElementPtr(dst_mem, index++), Read(src10));
  }
  if (UAnd(regs, uint16_t(0b1u << 11))) {
    Write(GetElementPtr(dst_mem, index++), Read(src11));
  }
  if (UAnd(regs, uint16_t(0b1u << 12))) {
    Write(GetElementPtr(dst_mem, index++), Read(src12));
  }
  if (UAnd(regs, uint16_t(0b1u << 13))) {
    Write(GetElementPtr(dst_mem, index++), Read(src13));
  }
  if (UAnd(regs, uint16_t(0b1u << 14))) {
    Write(GetElementPtr(dst_mem, index++), Read(src14));
  }
  if (UAnd(regs, uint16_t(0b1u << 15))) {
    Write(GetElementPtr(dst_mem, index++), Read(src15));
  }
  Write(dst, Read(dst_new));

  // ignore maybe_next_pc_dst
  (void) maybe_next_pc_dst;
  return memory;
}
}  // namespace

DEF_ISEL(STMDA) = STMDB;
DEF_ISEL(LDMDA) = LDM;
DEF_ISEL(STM) = STMDB;
DEF_ISEL(LDM) = LDM;

// DEF_ISEL(STMu) = STMu;
DEF_ISEL(STMDB) = STMDB;
DEF_ISEL(LDMDB) = LDM;

// DEF_ISEL(LDMu) = LDMu;
DEF_ISEL(STMIB) = STMDB;
DEF_ISEL(LDMIB) = LDM;

// DEF_ISEL(LDMe) = LDMe;
