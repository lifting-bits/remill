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

namespace {

DEF_SEM(DoRDTSC) {
  return __remill_sync_hyper_call(state, memory, SyncHyperCall::kX86ReadTSC);
}

DEF_SEM(DoRDTSCP) {
  return __remill_sync_hyper_call(state, memory, SyncHyperCall::kX86ReadTSCP);
}

DEF_SEM(LGDT, M32 src) {
  memory =
      __remill_sync_hyper_call(state, memory, SyncHyperCall::kAssertPrivileged);
  state.addr_to_load = AddressOf(src);
  return __remill_sync_hyper_call(state, memory,
                                  SyncHyperCall::kX86LoadGlobalDescriptorTable);
}

DEF_SEM(LIDT, M32 src) {
  memory =
      __remill_sync_hyper_call(state, memory, SyncHyperCall::kAssertPrivileged);
  state.addr_to_load = AddressOf(src);
  return __remill_sync_hyper_call(
      state, memory, SyncHyperCall::kX86LoadInterruptDescriptorTable);
}

DEF_SEM(DoRDMSR) {
  memory =
      __remill_sync_hyper_call(state, memory, SyncHyperCall::kAssertPrivileged);
  return __remill_sync_hyper_call(state, memory,
                                  SyncHyperCall::kX86ReadModelSpecificRegister);
}

DEF_SEM(DoWRMSR) {
  memory =
      __remill_sync_hyper_call(state, memory, SyncHyperCall::kAssertPrivileged);
  return __remill_sync_hyper_call(
      state, memory, SyncHyperCall::kX86WriteModelSpecificRegister);
}

DEF_SEM(DoWBINVD) {
  memory =
      __remill_sync_hyper_call(state, memory, SyncHyperCall::kAssertPrivileged);
  return __remill_sync_hyper_call(state, memory,
                                  SyncHyperCall::kX86WriteBackInvalidate);
}

template <SyncHyperCall::Name kSetCR>
DEF_SEM(WRITE_CONTROL_REG_32, R64W dst, R32 src) {
  memory =
      __remill_sync_hyper_call(state, memory, SyncHyperCall::kAssertPrivileged);
  WriteZExt(dst, Read(src));
  auto u = __remill_undefined_8();
  Write(FLAG_OF, u);
  Write(FLAG_SF, u);
  Write(FLAG_ZF, u);
  Write(FLAG_AF, u);
  Write(FLAG_PF, u);
  Write(FLAG_CF, u);
  return __remill_sync_hyper_call(state, memory, kSetCR);
}

DEF_SEM(READ_CONTROL_REG_32, R32W dst, R64 src) {
  memory =
      __remill_sync_hyper_call(state, memory, SyncHyperCall::kAssertPrivileged);
  WriteZExt(dst, Trunc(Read(src)));
  auto u = __remill_undefined_8();
  Write(FLAG_OF, u);
  Write(FLAG_SF, u);
  Write(FLAG_ZF, u);
  Write(FLAG_AF, u);
  Write(FLAG_PF, u);
  Write(FLAG_CF, u);
  return memory;
}

#if ADDRESS_SIZE_BITS == 64
DEF_SEM(READ_CONTROL_REG_64, R64W dst, R64 src) {
  memory =
      __remill_sync_hyper_call(state, memory, SyncHyperCall::kAssertPrivileged);
  Write(dst, Read(src));
  auto u = __remill_undefined_8();
  Write(FLAG_OF, u);
  Write(FLAG_SF, u);
  Write(FLAG_ZF, u);
  Write(FLAG_AF, u);
  Write(FLAG_PF, u);
  Write(FLAG_CF, u);
  return memory;
}

template <SyncHyperCall::Name kSetCR>
DEF_SEM(WRITE_CONTROL_REG_64, R64W dst, R64 src) {
  memory =
      __remill_sync_hyper_call(state, memory, SyncHyperCall::kAssertPrivileged);
  Write(dst, Read(src));
  auto u = __remill_undefined_8();
  Write(FLAG_OF, u);
  Write(FLAG_SF, u);
  Write(FLAG_ZF, u);
  Write(FLAG_AF, u);
  Write(FLAG_PF, u);
  Write(FLAG_CF, u);
  return __remill_sync_hyper_call(state, memory, kSetCR);
}
#endif

DEF_SEM(WRITE_DEBUG_REG_32, R64W dst, R32 src) {
  memory =
      __remill_sync_hyper_call(state, memory, SyncHyperCall::kAssertPrivileged);
  WriteZExt(dst, Read(src));
  auto u = __remill_undefined_8();
  Write(FLAG_OF, u);
  Write(FLAG_SF, u);
  Write(FLAG_ZF, u);
  Write(FLAG_AF, u);
  Write(FLAG_PF, u);
  Write(FLAG_CF, u);
  return __remill_sync_hyper_call(state, memory,
                                  SyncHyperCall::kX86SetDebugReg);
}

#if ADDRESS_SIZE_BITS == 64
DEF_SEM(WRITE_DEBUG_REG_64, R64W dst, R64 src) {
  memory =
      __remill_sync_hyper_call(state, memory, SyncHyperCall::kAssertPrivileged);
  Write(dst, Read(src));
  auto u = __remill_undefined_8();
  Write(FLAG_OF, u);
  Write(FLAG_SF, u);
  Write(FLAG_ZF, u);
  Write(FLAG_AF, u);
  Write(FLAG_PF, u);
  Write(FLAG_CF, u);
  return __remill_sync_hyper_call(state, memory,
                                  SyncHyperCall::kAMD64SetDebugReg);
}
#endif
}  // namespace

DEF_ISEL(RDTSC) = DoRDTSC;
DEF_ISEL(RDTSCP) = DoRDTSCP;
DEF_ISEL(RDMSR) = DoRDMSR;
DEF_ISEL(WRMSR) = DoWRMSR;
DEF_ISEL(WBINVD) = DoWBINVD;
DEF_ISEL(LGDT_MEMs_32) = LGDT;
DEF_ISEL(LIDT_MEMs_32) = LIDT;
DEF_ISEL(MOV_CR_CR_GPR32_CR0) =
    WRITE_CONTROL_REG_32<SyncHyperCall::kX86SetControlReg0>;
DEF_ISEL(MOV_CR_CR_GPR32_CR1) =
    WRITE_CONTROL_REG_32<SyncHyperCall::kX86SetControlReg1>;
DEF_ISEL(MOV_CR_CR_GPR32_CR2) =
    WRITE_CONTROL_REG_32<SyncHyperCall::kX86SetControlReg2>;
DEF_ISEL(MOV_CR_CR_GPR32_CR3) =
    WRITE_CONTROL_REG_32<SyncHyperCall::kX86SetControlReg3>;
DEF_ISEL(MOV_CR_CR_GPR32_CR4) =
    WRITE_CONTROL_REG_32<SyncHyperCall::kX86SetControlReg4>;
DEF_ISEL(MOV_CR_GPR32_CR) = READ_CONTROL_REG_32;
IF_64BIT(DEF_ISEL(MOV_CR_CR_GPR64_CR0) =
             WRITE_CONTROL_REG_64<SyncHyperCall::kAMD64SetControlReg0>;)
IF_64BIT(DEF_ISEL(MOV_CR_CR_GPR64_CR1) =
             WRITE_CONTROL_REG_64<SyncHyperCall::kAMD64SetControlReg1>;)
IF_64BIT(DEF_ISEL(MOV_CR_CR_GPR64_CR2) =
             WRITE_CONTROL_REG_64<SyncHyperCall::kAMD64SetControlReg2>;)
IF_64BIT(DEF_ISEL(MOV_CR_CR_GPR64_CR3) =
             WRITE_CONTROL_REG_64<SyncHyperCall::kAMD64SetControlReg3>;)
IF_64BIT(DEF_ISEL(MOV_CR_CR_GPR64_CR4) =
             WRITE_CONTROL_REG_64<SyncHyperCall::kAMD64SetControlReg4>;)
IF_64BIT(DEF_ISEL(MOV_CR_CR_GPR64_CR8) =
             WRITE_CONTROL_REG_64<SyncHyperCall::kAMD64SetControlReg8>;)
IF_64BIT(DEF_ISEL(MOV_CR_GPR64_CR) = READ_CONTROL_REG_64;)

DEF_ISEL(MOV_DR_DR_GPR32) = WRITE_DEBUG_REG_32;
IF_64BIT(DEF_ISEL(MOV_DR_DR_GPR64) = WRITE_DEBUG_REG_64;)
