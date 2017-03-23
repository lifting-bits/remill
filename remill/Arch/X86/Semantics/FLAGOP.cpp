/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_X86_SEMANTICS_FLAGOP_H_
#define REMILL_ARCH_X86_SEMANTICS_FLAGOP_H_

namespace {
DEF_SEM(DoCLD) {
  FLAG_DF = false;
  return memory;
}

DEF_SEM(DoSTD) {
  FLAG_DF = true;
  return memory;
}

DEF_SEM(DoCLC) {
  FLAG_CF = false;
  return memory;
}

DEF_SEM(DoCMC) {
  FLAG_CF = BNot(FLAG_CF);
  return memory;
}

DEF_SEM(DoSTC) {
  FLAG_CF = BNot(FLAG_CF);
  return memory;
}

DEF_SEM(DoSALC) {
  Write(REG_AL, Unsigned(FLAG_CF));
  return memory;
}

DEF_SEM(DoSAHF) {
  Flags flags = {ZExtTo<uint64_t>(Read(REG_AH))};
  FLAG_CF = UCmpEq(1, flags.cf);
  FLAG_PF = UCmpEq(1, flags.pf);
  FLAG_AF = UCmpEq(1, flags.af);
  FLAG_SF = UCmpEq(1, flags.sf);
  FLAG_ZF = UCmpEq(1, flags.zf);
  return memory;
}

DEF_SEM(DoLAHF) {
  Flags flags = {0};
  flags.cf = Unsigned(FLAG_CF);
  flags.must_be_1 = 1;
  flags.pf = Unsigned(FLAG_PF);
  flags.must_be_0a = 0;
  flags.af = Unsigned(FLAG_AF);
  flags.must_be_0b = 0;
  flags.zf = Unsigned(FLAG_ZF);
  flags.sf = Unsigned(FLAG_SF);
  Write(REG_AH, TruncTo<uint8_t>(flags.flat));
  return memory;
}

DEF_SEM(DoCLAC) {
  memory = __remill_sync_hyper_call(
      memory, state, SyncHyperCall::kAssertPrivileged);
  state.rflag.ac = false;
  return memory;
}

DEF_SEM(DoSTAC) {
  memory = __remill_sync_hyper_call(
      memory, state, SyncHyperCall::kAssertPrivileged);
  state.rflag.ac = true;
  return memory;
}

DEF_SEM(DoCLI) {
  memory = __remill_sync_hyper_call(
      memory, state, SyncHyperCall::kAssertPrivileged);
  state.rflag._if = false;
  return memory;
}

DEF_SEM(DoSTI) {
  memory = __remill_sync_hyper_call(
      memory, state, SyncHyperCall::kAssertPrivileged);
  state.rflag._if = true;
  return memory;
}
}  // namespace

DEF_ISEL(CLD) = DoCLD;
DEF_ISEL(STD) = DoSTD;
DEF_ISEL(CLC) = DoCLC;
DEF_ISEL(CMC) = DoCMC;
DEF_ISEL(STC) = DoSTC;
DEF_ISEL(SALC) = DoSALC;
DEF_ISEL(SAHF) = DoSAHF;
DEF_ISEL(LAHF) = DoLAHF;
DEF_ISEL(CLAC) = DoCLAC;
DEF_ISEL(STAC) = DoSTAC;
DEF_ISEL(CLI) = DoCLI;
DEF_ISEL(STI) = DoSTI;
#endif  // REMILL_ARCH_X86_SEMANTICS_FLAGOP_H_
