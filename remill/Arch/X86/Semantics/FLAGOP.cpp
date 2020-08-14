/*
 * Copyright (c) 2017 Trail of Bits, Inc.
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
  FLAG_CF = true;
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
  memory =
      __remill_sync_hyper_call(state, memory, SyncHyperCall::kAssertPrivileged);
  state.rflag.ac = false;
  return memory;
}

DEF_SEM(DoSTAC) {
  memory =
      __remill_sync_hyper_call(state, memory, SyncHyperCall::kAssertPrivileged);
  state.rflag.ac = true;
  return memory;
}

DEF_SEM(DoCLI) {
  memory =
      __remill_sync_hyper_call(state, memory, SyncHyperCall::kAssertPrivileged);
  state.rflag._if = false;
  return memory;
}

DEF_SEM(DoSTI) {
  memory =
      __remill_sync_hyper_call(state, memory, SyncHyperCall::kAssertPrivileged);
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
