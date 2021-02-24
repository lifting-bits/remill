/*
 * Copyright (c) 2019 Trail of Bits, Inc.
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

#pragma once

namespace {

DEF_SEM(NOP) {
  return memory;
}

DEF_SEM(FLUSH, M64 src) {
  return memory;
}


DEF_SEM(MEMBAR, I32 mask1, I32 mask2) {
#ifdef DEF_MEMBAR
  auto mmask = Read(mask1);
  if (mmask == 0) {
    return memory;
  }
  if (mmask & 0x1) {
    BarrierLoadLoad();
  }
  if (mmask & 0x2) {
    BarrierStoreLoad();
  }
  if (mmask & 0x4) {
    BarrierLoadStore();
  }
  if (mmask & 0x8) {
    BarrierStoreStore();
  }
#endif
  return memory;
}

DEF_SEM(PREFETCH, M64 address, I32 fcn) {
  return memory;
}

DEF_SEM(PREFETCHA, R8 asi, M64 address, I32 fcn) {
  HYPER_CALL_VECTOR = Read(asi);
  return __remill_sync_hyper_call(state, memory,
                                  SyncHyperCall::kSPARCSetAsiRegister);
}

}  // namespace

DEF_ISEL(NOP) = NOP;
DEF_ISEL(MEMBAR) = MEMBAR;
DEF_ISEL(FLUSHW) = NOP;
DEF_ISEL(FLUSH) = FLUSH;
DEF_ISEL(PREFETCH) = PREFETCH;
DEF_ISEL(PREFETCHA) = PREFETCHA;

namespace {

template <typename S1, typename S2, typename D>
DEF_SEM(SAVE, S1 src1, S2 src2, D dst, RegisterWindow *window,
        RegisterWindow *&prev_window) {
  addr_t sp_base = Read(src1);
  addr_t sp_offset = Read(src2);
  addr_t new_sp = UAdd(sp_base, sp_offset);
  SAVE_WINDOW(memory, state, window, prev_window);
  WriteZExt(dst, new_sp);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(RESTORE, S1 src1, S2 src2, D dst, RegisterWindow *&prev_window) {
  auto rs1 = Read(src1);
  auto rs2 = Read(src2);
  auto sum = UAdd(rs1, rs2);
  RESTORE_WINDOW(memory, state, prev_window);
  WriteZExt(dst, sum);
  return memory;
}

}  // namespace

DEF_ISEL(SAVE) = SAVE<R64, I64, R64W>;
DEF_ISEL(RESTORE) = RESTORE<R64, I64, R64W>;
