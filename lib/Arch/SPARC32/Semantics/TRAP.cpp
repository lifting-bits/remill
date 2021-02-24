/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 */

// Makes an asynchronous and synchronous version of the trap. The asynchronous
// exists during normal control-flow, and introduces its own control flow and
// an async hyper call. The synchronous version exists when the trap instruction
// is placed inside of a delay slot.
#define MAKE_TRAP(cond, cc) \
  namespace { \
  DEF_SEM(T##cond, R8W branch_taken, PC new_pc, PC new_npc, I32 vec_a, \
          I32 vec_b, R32W pc_dst, R32W npc_dst) { \
    Write(branch_taken, Cond##cond##_##cc(state)); \
    HYPER_CALL = AsyncHyperCall::kSPARCTrapCond##cond; \
    HYPER_CALL_VECTOR = UAnd(UAdd(Read(vec_a), Read(vec_b)), 0x7fu); \
    return memory; \
  } \
  DEF_SEM(T##cond##_sync, R8W branch_taken, PC new_pc, PC new_npc, I32 vec_a, \
          I32 vec_b, R32W pc_dst, R32W npc_dst) { \
    Write(branch_taken, Cond##cond##_##cc(state)); \
    HYPER_CALL = AsyncHyperCall::kSPARCTrapCond##cond; \
    HYPER_CALL_VECTOR = UAnd(UAdd(Read(vec_a), Read(vec_b)), 0x7fu); \
    return __remill_sync_hyper_call(state, memory, \
                                    SyncHyperCall::kSPARCTrapCond##cond); \
  } \
  } \
  DEF_ISEL(T##cond) = T##cond; \
  DEF_ISEL(T##cond##_sync) = T##cond##_sync

namespace {

DEF_SEM(TA, R8W branch_taken, PC new_pc, PC new_npc, I32 vec_a, I32 vec_b,
        R32W pc_dst, R32W npc_dst) {
  HYPER_CALL = AsyncHyperCall::kSPARCTrapCondA;
  HYPER_CALL_VECTOR = UAnd(UAdd(Read(vec_a), Read(vec_b)), 0x7fu);
  Write(branch_taken, true);
  return memory;
}

DEF_SEM(TA_sync, R8W branch_taken, PC new_pc, PC new_npc, I32 vec_a, I32 vec_b,
        R32W pc_dst, R32W npc_dst) {
  HYPER_CALL = AsyncHyperCall::kSPARCTrapCondA;
  HYPER_CALL_VECTOR = UAnd(UAdd(Read(vec_a), Read(vec_b)), 0x7fu);
  return __remill_sync_hyper_call(state, memory,
                                  SyncHyperCall::kSPARCTrapCondA);
}

DEF_SEM(TN, R8W branch_taken, PC new_pc, PC new_npc, I32 vec_a, I32 vec_b,
        R32W pc_dst, R32W npc_dst) {
  Write(pc_dst, Read(new_pc));
  Write(npc_dst, Read(new_npc));
  return memory;
}

DEF_SEM(TN_sync, R8W branch_taken, PC new_pc, PC new_npc, I32 vec_a, I32 vec_b,
        R64W pc_dst, R64W npc_dst) {
  return memory;
}

}  // namespace

DEF_ISEL(TA) = TA;
DEF_ISEL(TA_sync) = TA_sync;
DEF_ISEL(TN) = TN;
DEF_ISEL(TN_sync) = TN_sync;

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

#undef MAKE_TRAP

namespace {

DEF_SEM(UNIMP_SYNC, I32 struct_size) {

  // TODO(pag): See if callees inspect the struct size when this is after the
  //            delay slot of a CALL. See "Programming Note" in v8 manual, B.31,
  //            p137.
  HYPER_CALL_VECTOR = Read(struct_size);
  return __remill_sync_hyper_call(
      state, memory, SyncHyperCall::kSPARCUnimplementedInstruction);
}

DEF_SEM(UNIMP_ASYNC, I32 struct_size) {

  // TODO(pag): See if callees inspect the struct size when this is after the
  //            delay slot of a CALL. See "Programming Note" in v8 manual, B.31,
  //            p137.
  HYPER_CALL_VECTOR = Read(struct_size);
  HYPER_CALL = AsyncHyperCall::kSPARCUnimplementedInstruction;
  return memory;
}

}  // namespace

DEF_ISEL(UNIMP_SYNC) = UNIMP_SYNC;  // In a delay slot.
DEF_ISEL(UNIMP_ASYNC) = UNIMP_ASYNC;  // Not in a delay slot.
