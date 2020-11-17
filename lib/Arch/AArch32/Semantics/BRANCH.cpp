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

DEF_SEM(B, R8, R8W, I32 taken_pc, R32W next_pc_dst) {
  auto new_pc = Read(taken_pc);
  Write(state.gpr.r15.dword, new_pc);
  Write(next_pc_dst, new_pc);
  return memory;
}

DEF_SEM(BCOND, R8 cond, R8W branch_taken, I32 taken_pc, I32 not_taken_pc,
             R32W next_pc_dst) {
  auto c = Read(cond);
  auto new_pc = Select(c, Read(taken_pc), Read(not_taken_pc));
  Write(state.gpr.r15.dword, new_pc);
  Write(next_pc_dst, new_pc);
  Write(branch_taken, c);
  return memory;
}

} //namespace

DEF_ISEL(B) = B;
DEF_ISEL(BCOND) = BCOND;
