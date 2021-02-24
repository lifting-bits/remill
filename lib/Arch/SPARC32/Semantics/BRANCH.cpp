/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 */

namespace {

// NOTE(pag): `new_pc == pc_of_jmp + 4`, and `new_npc`
//            is the target EA.
template <typename T>
DEF_SEM(JMPL, PC pc_of_jmp, PC new_pc, PC new_npc, T dst, T dst_pc, T dst_npc) {
  auto new_dst = Read(pc_of_jmp);
  auto new_dst_pc = Read(new_pc);
  auto new_dst_npc = Read(new_npc);
  Write(dst, new_dst);
  Write(dst_pc, new_dst_pc);
  Write(dst_npc, new_dst_npc);
  return memory;
}

// This is a variation on JMPL that also stores the return address.
template <typename T>
DEF_SEM(CALL, PC pc_of_jmp, PC new_pc, PC new_npc, T dst, T dst_pc, T dst_npc,
        T return_pc_dst) {
  Write(dst, Read(pc_of_jmp));
  Write(dst_pc, Read(new_pc));
  Write(dst_npc, Read(new_npc));

  // NOTE(pag): See comment above about conventions.
  Write(return_pc_dst, UAdd(Read(pc_of_jmp), 8));
  return memory;
}

// Makes an asynchronous and synchronous version of the trap. The asynchronous
// exists during normal control-flow, and introduces its own control flow and
// an async hyper call. The synchronous version exists when the trap instruction
// is placed inside of a delay slot.
#define MAKE_BRANCH(name, cond, cc) \
  namespace { \
  DEF_SEM(name##cond##_##cc, R8W branch_taken, PC new_taken_pc, \
          PC new_taken_npc, PC new_not_taken_pc, PC new_not_taken_npc, \
          R32W pc_dst, R32W npc_dst) { \
    if (Cond##cond##_##cc(state)) { \
      Write(branch_taken, true); \
      Write(pc_dst, Read(new_taken_pc)); \
      Write(npc_dst, Read(new_taken_npc)); \
    } else { \
      Write(branch_taken, false); \
      Write(pc_dst, Read(new_not_taken_pc)); \
      Write(npc_dst, Read(new_not_taken_npc)); \
    } \
    return memory; \
  } \
  } \
  DEF_ISEL(name##cond##_##cc) = name##cond##_##cc;

template <typename T>
DEF_SEM(BA, PC new_taken_pc, PC new_taken_npc, T pc_dst, T npc_dst) {
  Write(pc_dst, Read(new_taken_pc));
  Write(npc_dst, Read(new_taken_npc));
  return memory;
}

template <typename T>
DEF_SEM(BN, PC new_not_taken_pc, PC new_not_taken_npc, T pc_dst, T npc_dst) {
  Write(pc_dst, Read(new_not_taken_pc));
  Write(npc_dst, Read(new_not_taken_npc));
  return memory;
}

template <typename T>
DEF_SEM(FBA, PC new_taken_pc, PC new_taken_npc, T pc_dst, T npc_dst) {
  Write(pc_dst, Read(new_taken_pc));
  Write(npc_dst, Read(new_taken_npc));
  return memory;
}

template <typename T>
DEF_SEM(FBN, PC new_not_taken_pc, PC new_not_taken_npc, T pc_dst, T npc_dst) {
  Write(pc_dst, Read(new_not_taken_pc));
  Write(npc_dst, Read(new_not_taken_npc));
  return memory;
}

// A branch instruction existing in a delay slot. These are DCTI couples. They
// have weird pipeline effects, e.g.
//
//      address         instruction         target
//      ------------+------------------+--------------
//      8             not-a-cti
//      12            cti                 40
//      16            cti                 60
//      20            not-a-cti
//      24            ...
//
//      40            not-a-cti
//      44            ...
//
//      60            not-a-cti
//      64            ...
//
//      case          12: cti 40        16: cti 60      order of execution
//      -----+---------------------+-----------------+---------------------
//      1     dcti unconditional    dcti taken         12,16,40,60,64,...
//      2     dcti unconditional    B*cc(a=0) untaken  12,16,40,44
//      3     dcti unconditional    B*cc(a=1) untaken  12,16,44,48 (40 annulled)
//      4     dcti unconditional    B*A(a=1)           12,16,60,64 (40 annulled)
//      5     B*A(a=1)              any cti            12,40,44,... (16 annulled)
//      6     B*cc                  dcti               12,unpredictable
DEF_SEM(UNSUPPORTED_DCTI) {
  return __remill_sync_hyper_call(state, memory,
                                  SyncHyperCall::kSPARCUnhandledDCTI);
}

// TODO(pag): Double check that `new_pc` reads `rs1/rs2` from the pre-
//            incremented register window state.
template <typename T>
DEF_SEM(RETT, PC new_pc, PC new_npc, T dst_pc, T dst_npc,
        RegisterWindow *&prev_window) {
  RESTORE_WINDOW(memory, state, prev_window);
  Write(dst_pc, Read(new_pc));
  Write(dst_npc, Read(new_npc));
  return memory;
}

}  // namespace

DEF_ISEL(UNSUPPORTED_DCTI) = UNSUPPORTED_DCTI;

DEF_ISEL(CALL) = CALL<R32W>;
DEF_ISEL(CALL_INDIRECT) = CALL<R32W>;
DEF_ISEL(JMPL) = JMPL<R32W>;
DEF_ISEL(RETL) = JMPL<R32W>;
DEF_ISEL(RETT) = RETT<R32W>;

DEF_ISEL(BA_icc) = BA<R32W>;
DEF_ISEL(BN_icc) = BN<R32W>;

DEF_ISEL(BA_xcc) = BA<R32W>;
DEF_ISEL(BN_xcc) = BN<R32W>;

DEF_ISEL(FBA_fcc0) = FBA<R32W>;
DEF_ISEL(FBA_fcc1) = FBA<R32W>;
DEF_ISEL(FBA_fcc2) = FBA<R32W>;
DEF_ISEL(FBA_fcc3) = FBA<R32W>;

DEF_ISEL(FBN_fcc0) = FBN<R32W>;
DEF_ISEL(FBN_fcc1) = FBN<R32W>;
DEF_ISEL(FBN_fcc2) = FBN<R32W>;
DEF_ISEL(FBN_fcc3) = FBN<R32W>;

#define MAKE_BRANCH_CC(name, cond) \
  MAKE_BRANCH(name, cond, icc) \
  MAKE_BRANCH(name, cond, xcc)

MAKE_BRANCH_CC(B, NE)
MAKE_BRANCH_CC(B, E)
MAKE_BRANCH_CC(B, G)
MAKE_BRANCH_CC(B, LE)
MAKE_BRANCH_CC(B, GE)
MAKE_BRANCH_CC(B, L)
MAKE_BRANCH_CC(B, GU)
MAKE_BRANCH_CC(B, LEU)
MAKE_BRANCH_CC(B, CC)
MAKE_BRANCH_CC(B, CS)
MAKE_BRANCH_CC(B, POS)
MAKE_BRANCH_CC(B, NEG)
MAKE_BRANCH_CC(B, VC)
MAKE_BRANCH_CC(B, VS)

#define MAKE_BRANCH_F(name, cond) \
  MAKE_BRANCH(name, cond, fcc0) \
  MAKE_BRANCH(name, cond, fcc1) \
  MAKE_BRANCH(name, cond, fcc2) \
  MAKE_BRANCH(name, cond, fcc3)

MAKE_BRANCH_F(FB, U)
MAKE_BRANCH_F(FB, G)
MAKE_BRANCH_F(FB, UG)
MAKE_BRANCH_F(FB, L)
MAKE_BRANCH_F(FB, UL)
MAKE_BRANCH_F(FB, LG)
MAKE_BRANCH_F(FB, NE)
MAKE_BRANCH_F(FB, E)
MAKE_BRANCH_F(FB, UE)
MAKE_BRANCH_F(FB, GE)
MAKE_BRANCH_F(FB, UGE)
MAKE_BRANCH_F(FB, LE)
MAKE_BRANCH_F(FB, ULE)
MAKE_BRANCH_F(FB, O)


#undef MAKE_BRANCH
#undef MAKE_BRANCH_F


// Branch on Coprocessor Condition Codes Instructions

#define MAKE_BRANCH(name, cond) \
  namespace { \
  DEF_SEM(name##cond, R8W branch_taken, PC new_taken_pc, PC new_taken_npc, \
          PC new_not_taken_pc, PC new_not_taken_npc, R32W pc_dst, \
          R32W npc_dst) { \
    if (Cond##cond##_ccc(state)) { \
      Write(branch_taken, true); \
      Write(pc_dst, Read(new_taken_pc)); \
      Write(npc_dst, Read(new_taken_npc)); \
    } else { \
      Write(branch_taken, false); \
      Write(pc_dst, Read(new_not_taken_pc)); \
      Write(npc_dst, Read(new_not_taken_npc)); \
    } \
    return memory; \
  } \
  } \
  DEF_ISEL(name##cond) = name##cond;

MAKE_BRANCH(CB, A)
MAKE_BRANCH(CB, N)
MAKE_BRANCH(CB, 3)
MAKE_BRANCH(CB, 2)
MAKE_BRANCH(CB, 23)
MAKE_BRANCH(CB, 1)
MAKE_BRANCH(CB, 13)
MAKE_BRANCH(CB, 12)
MAKE_BRANCH(CB, 123)
MAKE_BRANCH(CB, 0)
MAKE_BRANCH(CB, 03)
MAKE_BRANCH(CB, 02)
MAKE_BRANCH(CB, 023)
MAKE_BRANCH(CB, 01)
MAKE_BRANCH(CB, 013)
MAKE_BRANCH(CB, 012)

#undef MAKE_BRANCH
