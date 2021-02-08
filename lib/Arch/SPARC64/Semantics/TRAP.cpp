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

// Makes an asynchronous and synchronous version of the trap. The asynchronous
// exists during normal control-flow, and introduces its own control flow and
// an async hyper call. The synchronous version exists when the trap instruction
// is placed inside of a delay slot.
#define MAKE_TRAP(cond, cc) \
  namespace { \
  DEF_SEM(T##cond##_##cc, R8W branch_taken, PC new_pc, PC new_npc, I32 vec_a, \
          I32 vec_b, R64W pc_dst, R64W npc_dst) { \
    Write(branch_taken, Cond##cond##_##cc(state)); \
    HYPER_CALL = AsyncHyperCall::kSPARCTrapCond##cond; \
    HYPER_CALL_VECTOR = UAnd(UAdd(Read(vec_a), Read(vec_b)), 0x7fu); \
    return memory; \
  } \
  DEF_SEM(T##cond##_sync##_##cc, R8W branch_taken, PC new_pc, PC new_npc, \
          I32 vec_a, I32 vec_b, R64W pc_dst, R64W npc_dst) { \
    Write(branch_taken, Cond##cond##_##cc(state)); \
    HYPER_CALL = AsyncHyperCall::kSPARCTrapCond##cond; \
    HYPER_CALL_VECTOR = UAnd(UAdd(Read(vec_a), Read(vec_b)), 0x7fu); \
    return __remill_sync_hyper_call(state, memory, \
                                    SyncHyperCall::kSPARCTrapCond##cond); \
  } \
  } \
  DEF_ISEL(T##cond##_##cc) = T##cond##_##cc; \
  DEF_ISEL(T##cond##_sync##_##cc) = T##cond##_sync##_##cc

namespace {

DEF_SEM(TA, R8W branch_taken, PC new_pc, PC new_npc, I32 vec_a, I32 vec_b,
        R64W pc_dst, R64W npc_dst) {
  HYPER_CALL = AsyncHyperCall::kSPARCTrapCondA;
  HYPER_CALL_VECTOR = UAnd(UAdd(Read(vec_a), Read(vec_b)), 0x7fu);
  Write(branch_taken, true);
  return memory;
}

DEF_SEM(TA_sync, R8W branch_taken, PC new_pc, PC new_npc, I32 vec_a, I32 vec_b,
        R64W pc_dst, R64W npc_dst) {
  HYPER_CALL = AsyncHyperCall::kSPARCTrapCondA;
  HYPER_CALL_VECTOR = UAnd(UAdd(Read(vec_a), Read(vec_b)), 0x7fu);
  return __remill_sync_hyper_call(state, memory,
                                  SyncHyperCall::kSPARCTrapCondA);
}

DEF_SEM(TN, R8W branch_taken, PC new_pc, PC new_npc, I32 vec_a, I32 vec_b,
        R64W pc_dst, R64W npc_dst) {
  Write(pc_dst, Read(new_pc));
  Write(npc_dst, Read(new_npc));
  return memory;
}

DEF_SEM(TN_sync, R8W branch_taken, PC new_pc, PC new_npc, I32 vec_a, I32 vec_b,
        R64W pc_dst, R64W npc_dst) {
  return memory;
}

}  // namespace

DEF_ISEL(TA_icc) = TA;
DEF_ISEL(TA_xcc) = TA;
DEF_ISEL(TA_icc_sync) = TA_sync;
DEF_ISEL(TA_xcc_sync) = TA_sync;
DEF_ISEL(TN_icc) = TN;
DEF_ISEL(TN_xcc) = TN;
DEF_ISEL(TN_icc_sync) = TN_sync;
DEF_ISEL(TN_xcc_sync) = TN_sync;

MAKE_TRAP(NE, icc);
MAKE_TRAP(E, icc);
MAKE_TRAP(G, icc);
MAKE_TRAP(LE, icc);
MAKE_TRAP(GE, icc);
MAKE_TRAP(L, icc);
MAKE_TRAP(GU, icc);
MAKE_TRAP(LEU, icc);
MAKE_TRAP(CC, icc);
MAKE_TRAP(CS, icc);
MAKE_TRAP(POS, icc);
MAKE_TRAP(NEG, icc);
MAKE_TRAP(VC, icc);
MAKE_TRAP(VS, icc);

MAKE_TRAP(NE, xcc);
MAKE_TRAP(E, xcc);
MAKE_TRAP(G, xcc);
MAKE_TRAP(LE, xcc);
MAKE_TRAP(GE, xcc);
MAKE_TRAP(L, xcc);
MAKE_TRAP(GU, xcc);
MAKE_TRAP(LEU, xcc);
MAKE_TRAP(CC, xcc);
MAKE_TRAP(CS, xcc);
MAKE_TRAP(POS, xcc);
MAKE_TRAP(NEG, xcc);
MAKE_TRAP(VC, xcc);
MAKE_TRAP(VS, xcc);

namespace {

// TODO(akshay) Please refer `remill/Arch/SPARC32/Semantics/TRAP.cpp`
// `illtrap` behaviour is same as `unimp` in sparc V8

DEF_SEM(ILLTRAP_SYNC, I32 struct_size) {
  HYPER_CALL_VECTOR = Read(struct_size);
  return __remill_sync_hyper_call(
      state, memory, SyncHyperCall::kSPARCUnimplementedInstruction);
}

DEF_SEM(ILLTRAP_ASYNC, I32 struct_size) {
  HYPER_CALL_VECTOR = Read(struct_size);
  HYPER_CALL = AsyncHyperCall::kSPARCUnimplementedInstruction;
  return memory;
}

}  // namespace

DEF_ISEL(ILLTRAP_SYNC) = ILLTRAP_SYNC;  // In a delay slot.
DEF_ISEL(ILLTRAP_ASYNC) = ILLTRAP_ASYNC;  // Not in a delay slot.
