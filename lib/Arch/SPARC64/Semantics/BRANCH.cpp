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

template <typename T>
DEF_SEM(JMPL, PC pc_of_jmp, PC new_pc, PC new_npc, T dst, T dst_pc, T dst_npc) {
  Write(dst, Read(pc_of_jmp));
  Write(dst_pc, Read(new_pc));
  Write(dst_npc, Read(new_npc));
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

template <typename T>
DEF_SEM(RETURN, PC new_pc, PC new_npc, T dst_pc, T dst_npc,
        RegisterWindow *&prev_window) {
  RESTORE_WINDOW(memory, state, prev_window);
  Write(dst_pc, Read(new_pc));
  Write(dst_npc, Read(new_npc));
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
          R64W pc_dst, R64W npc_dst) { \
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

DEF_SEM(UNSUPPORTED_DCTI) {
  return __remill_sync_hyper_call(state, memory,
                                  SyncHyperCall::kSPARCUnhandledDCTI);
}

}  // namespace

DEF_ISEL(UNSUPPORTED_DCTI) = UNSUPPORTED_DCTI;

DEF_ISEL(CALL) = CALL<R64W>;
DEF_ISEL(CALL_INDIRECT) = CALL<R64W>;

DEF_ISEL(JMPL) = JMPL<R64W>;
DEF_ISEL(RETL) = JMPL<R64W>;
DEF_ISEL(RETURN) = RETURN<R64W>;

DEF_ISEL(BA_icc) = BA<R64W>;
DEF_ISEL(BN_icc) = BN<R64W>;

DEF_ISEL(BA_xcc) = BA<R64W>;
DEF_ISEL(BN_xcc) = BN<R64W>;

DEF_ISEL(FBA_fcc0) = FBA<R64W>;
DEF_ISEL(FBA_fcc1) = FBA<R64W>;
DEF_ISEL(FBA_fcc2) = FBA<R64W>;
DEF_ISEL(FBA_fcc3) = FBA<R64W>;

DEF_ISEL(FBN_fcc0) = FBN<R64W>;
DEF_ISEL(FBN_fcc1) = FBN<R64W>;
DEF_ISEL(FBN_fcc2) = FBN<R64W>;
DEF_ISEL(FBN_fcc3) = FBN<R64W>;

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
  MAKE_BRANCH(name, cond, fcc0); \
  MAKE_BRANCH(name, cond, fcc1); \
  MAKE_BRANCH(name, cond, fcc2); \
  MAKE_BRANCH(name, cond, fcc3);

MAKE_BRANCH_F(FB, U);
MAKE_BRANCH_F(FB, G);
MAKE_BRANCH_F(FB, UG);
MAKE_BRANCH_F(FB, L);
MAKE_BRANCH_F(FB, UL);
MAKE_BRANCH_F(FB, LG);
MAKE_BRANCH_F(FB, NE);
MAKE_BRANCH_F(FB, E);
MAKE_BRANCH_F(FB, UE);
MAKE_BRANCH_F(FB, GE);
MAKE_BRANCH_F(FB, UGE);
MAKE_BRANCH_F(FB, LE);
MAKE_BRANCH_F(FB, ULE);
MAKE_BRANCH_F(FB, O);


#undef MAKE_BRANCH
#undef MAKE_BRANCH_F

#define MAKE_BRANCH(name, cond) \
  namespace { \
  template <typename S> \
  DEF_SEM(name##cond, R8W branch_taken, S reg_cc, PC new_taken_pc, \
          PC new_taken_npc, PC new_not_taken_pc, PC new_not_taken_npc, \
          R64W pc_dst, R64W npc_dst) { \
    auto cc = Read(reg_cc); \
    if (CondR##cond(state, cc)) { \
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
  DEF_ISEL(name##cond) = name##cond<R64>;

MAKE_BRANCH(BR, Z)
MAKE_BRANCH(BR, LEZ)
MAKE_BRANCH(BR, LZ)

MAKE_BRANCH(BR, NZ)
MAKE_BRANCH(BR, GZ)
MAKE_BRANCH(BR, GEZ)
