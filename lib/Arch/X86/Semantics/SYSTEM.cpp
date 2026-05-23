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

template <typename D>
DEF_SEM(RDFSBASE, D dst) {
  WriteZExt(dst, TruncTo<D>(Read(REG_FS_BASE)));
  return memory;
}

template <typename D>
DEF_SEM(RDSSP_DISABLED, D) {
  return memory;
}

DEF_SEM(SMSW_GPR16, R16W dst) {
  Write(dst, 0x31_u16);
  return memory;
}

DEF_SEM(SMSW_GPR32, R32W dst) {
  WriteZExt(dst, 0x80050031_u32);
  return memory;
}

IF_64BIT(DEF_SEM(SMSW_GPR64, R64W dst) {
  Write(dst, 0x80050031_u64);
  return memory;
})

template <typename D, typename S>
DEF_SEM(LAR, D dst, S src) {
  const auto old_dst = Read(dst);
  const auto selector = TruncTo<uint16_t>(Read(src));
  const auto is_user_data = UCmpEq(selector, 0x20_u16);
  const auto is_user_data_rpl1 = UCmpEq(selector, 0x21_u16);
  const auto is_user_code = UCmpEq(selector, 0x28_u16);
  const auto is_system_tss = UCmpEq(selector, 0x50_u16);
  const auto valid = BOr(BOr(BOr(is_user_data, is_user_data_rpl1),
                            is_user_code),
                         is_system_tss);
  const auto user_access_rights = Select<uint32_t>(
      is_user_code, 0x0000f300_u32, 0x00cffb00_u32);
  const auto access_rights = Select<uint32_t>(
      is_system_tss, 0x0040f300_u32, user_access_rights);
  const auto new_dst = static_cast<decltype(old_dst)>(access_rights);
  FLAG_ZF = valid;
  Write(dst, Select(valid, new_dst, old_dst));
  return memory;
}

template <typename D, typename S1, typename S2>
DEF_SEM(LSL, D dst, S1, S2 src) {
  const auto old_dst = Read(dst);
  const auto selector = TruncTo<uint16_t>(Read(src));
  const auto is_user_data = UCmpEq(selector, 0x20_u16);
  const auto is_user_data_rpl2 = UCmpEq(selector, 0x22_u16);
  const auto is_user_code = UCmpEq(selector, 0x28_u16);
  const auto valid = BOr(BOr(is_user_data, is_user_data_rpl2), is_user_code);
  const auto new_dst = static_cast<decltype(old_dst)>(0xffffffff_u32);
  FLAG_ZF = valid;
  Write(dst, Select(valid, new_dst, old_dst));
  return memory;
}

template <typename S>
DEF_SEM(VERR, S src) {
  state.addr_to_load = ZExtTo<uint64_t>(TruncTo<uint16_t>(Read(src)));
  return __remill_sync_hyper_call(state, memory,
                                  SyncHyperCall::kX86VerifySegmentReadable);
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
DEF_ISEL(RDFSBASE_GPRy_32) = RDFSBASE<R32W>;
IF_64BIT(DEF_ISEL(RDFSBASE_GPRy_64) = RDFSBASE<R64W>;)
DEF_ISEL(RDSSPD_GPR32u32) = RDSSP_DISABLED<R32W>;
IF_64BIT(DEF_ISEL(RDSSPQ_GPR64u64) = RDSSP_DISABLED<R64W>;)
DEF_ISEL(SMSW_GPRv_16) = SMSW_GPR16;
DEF_ISEL(SMSW_GPRv_32) = SMSW_GPR32;
IF_64BIT(DEF_ISEL(SMSW_GPRv_64) = SMSW_GPR64;)
DEF_ISEL(RDMSR) = DoRDMSR;
DEF_ISEL(WRMSR) = DoWRMSR;
DEF_ISEL(WBINVD) = DoWBINVD;
DEF_ISEL(LGDT_MEMs_32) = LGDT;
DEF_ISEL(LIDT_MEMs_32) = LIDT;
DEF_ISEL(LAR_GPRv_MEMw_16) = LAR<R16W, M16>;
DEF_ISEL(LAR_GPRv_MEMw_32) = LAR<R32W, M16>;
IF_64BIT(DEF_ISEL(LAR_GPRv_MEMw_64) = LAR<R64W, M16>;)
DEF_ISEL(LAR_GPRv_GPRv_16) = LAR<R16W, R16>;
DEF_ISEL(LAR_GPRv_GPRv_32) = LAR<R32W, R32>;
IF_64BIT(DEF_ISEL(LAR_GPRv_GPRv_64) = LAR<R64W, R64>;)
DEF_ISEL(LSL_GPRv_MEMw_16) = LSL<R16W, R16, M16>;
DEF_ISEL(LSL_GPRv_MEMw_32) = LSL<R32W, R32, M16>;
IF_64BIT(DEF_ISEL(LSL_GPRv_MEMw_64) = LSL<R64W, R64, M16>;)
DEF_ISEL(LSL_GPRv_GPRz_16) = LSL<R16W, R16, R16>;
DEF_ISEL(LSL_GPRv_GPRz_32) = LSL<R32W, R32, R32>;
IF_64BIT(DEF_ISEL(LSL_GPRv_GPRz_64) = LSL<R64W, R64, R32>;)
DEF_ISEL(VERR_MEMw) = VERR<M16>;
DEF_ISEL(VERR_GPR16) = VERR<R16>;
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
