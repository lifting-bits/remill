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
DEF_SEM(B, R8, R8W, I32 taken_pc, PC next_pc_src, R32W next_pc_dst) {
  auto new_pc = Read(taken_pc);
  Write(REG_PC, new_pc);
  Write(next_pc_dst, new_pc);
  (void) next_pc_src;
  return memory;
}

DEF_SEM(BCOND, R8 cond, R8W branch_taken, I32 taken_pc, I32 not_taken_pc,
        R32W next_pc_dst) {
  auto c = Read(cond);
  auto new_pc = Select(c, Read(taken_pc), Read(not_taken_pc));
  Write(REG_PC, new_pc);
  Write(next_pc_dst, new_pc);
  Write(branch_taken, c);
  return memory;
}

DEF_SEM(BL, R8, R8W, PC target_addr, PC ret_addr, R32W next_pc_dst,
        R32W return_pc_dst) {
  const auto return_pc = Read(ret_addr);
  const auto new_pc = Read(target_addr);
  Write(REG_LR, return_pc);
  Write(REG_PC, new_pc);
  Write(next_pc_dst, new_pc);
  Write(return_pc_dst, return_pc);
  return memory;
}

DEF_SEM(BLCOND, R8 cond, R8W branch_taken, PC target_addr, PC ret_addr,
        R32W next_pc_dst, R32W return_pc_dst) {
  auto c = Read(cond);
  const auto return_pc = Read(ret_addr);
  if (c) {
    const auto target_pc = Read(target_addr);
    Write(REG_LR, return_pc);
    Write(REG_PC, target_pc);
    Write(next_pc_dst, target_pc);
  } else {
    Write(REG_PC, return_pc);
    Write(next_pc_dst, return_pc);
  }
  Write(return_pc_dst, return_pc);
  Write(branch_taken, c);
  return memory;
}
}  // namespace

DEF_ISEL(B) = B;
DEF_ISEL(BCOND) = BCOND;
DEF_ISEL(BL) = BL;
DEF_ISEL(BLCOND) = BLCOND;
DEF_ISEL(BLX) = BL;
DEF_ISEL(BLXCOND) = BLCOND;
DEF_ISEL(BX) = B;
DEF_ISEL(BXCOND) = BCOND;
