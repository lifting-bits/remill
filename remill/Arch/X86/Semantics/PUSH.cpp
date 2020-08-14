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

static void SerializeFlags(State &state) {
  state.rflag.cf = state.aflag.cf;

  //state.rflag.must_be_1 = 1;
  state.rflag.pf = state.aflag.pf;

  //state.rflag.must_be_0a = 0;
  state.rflag.af = state.aflag.af;

  //state.rflag.must_be_0b = 0;
  state.rflag.zf = state.aflag.zf;
  state.rflag.sf = state.aflag.sf;

  //state.rflag.tf = 0;  // Trap flag (not single-stepping).
  //state.rflag._if = 1;  // Interrupts are enabled (assumes user mode).
  state.rflag.df = state.aflag.df;
  state.rflag.of = state.aflag.of;

  //state.rflag.iopl = 0;  // In user-mode. TODO(pag): Configurable?
  //state.rflag.nt = 0;  // Not running in a nested task (interrupted interrupt).
  //state.rflag.must_be_0c = 0;
  //state.rflag.rf = 0; // Not specifying a resume from a breakpoint.
  //state.rflag.vm = 0;  // Virtual 8086 mode is disabled.
  //state.rflag.ac = 0;  // Assume alignment checking is disabled.
  //state.rflag.vif = 0;  // Virtual interrupts are disabled.
  //state.rflag.vip = 0; // No virtual interrupts are pending.
  //state.rflag.id = 0;  // Disallow `CPUID`.  TODO(pag): Configurable?
  //state.rflag.reserved_eflags = 0;  // bits 22-31.
}

}  // namespace

namespace {

template <typename T>
DEF_HELPER(PushToStack, T val)->void {
  addr_t op_size = ZExtTo<addr_t>(ByteSizeOf(val));
  addr_t old_xsp = Read(REG_XSP);
  addr_t new_xsp = USub(old_xsp, op_size);
  Write(WritePtr<T>(new_xsp _IF_32BIT(REG_SS_BASE)), val);
  Write(REG_XSP, new_xsp);
}

template <typename S1>
DEF_SEM(PUSH, S1 src1) {
  PushToStack(memory, state, Read(src1));
  return memory;
}

#if 32 == ADDRESS_SIZE_BITS || 1

DEF_SEM(DoPUSHA) {
  uint16_t sp = Read(REG_SP);
  PushToStack<uint16_t>(memory, state, Read(REG_AX));
  PushToStack<uint16_t>(memory, state, Read(REG_CX));
  PushToStack<uint16_t>(memory, state, Read(REG_DX));
  PushToStack<uint16_t>(memory, state, Read(REG_BX));
  PushToStack<uint16_t>(memory, state, sp);
  PushToStack<uint16_t>(memory, state, Read(REG_BP));
  PushToStack<uint16_t>(memory, state, Read(REG_SI));
  PushToStack<uint16_t>(memory, state, Read(REG_DI));
  return memory;
}

DEF_SEM(DoPUSHAD) {
  uint32_t esp = Read(REG_ESP);
  PushToStack<uint32_t>(memory, state, Read(REG_EAX));
  PushToStack<uint32_t>(memory, state, Read(REG_ECX));
  PushToStack<uint32_t>(memory, state, Read(REG_EDX));
  PushToStack<uint32_t>(memory, state, Read(REG_EBX));
  PushToStack<uint32_t>(memory, state, esp);
  PushToStack<uint32_t>(memory, state, Read(REG_EBP));
  PushToStack<uint32_t>(memory, state, Read(REG_ESI));
  PushToStack<uint32_t>(memory, state, Read(REG_EDI));
  return memory;
}
#endif

DEF_SEM(DoPUSHF) {
  SerializeFlags(state);
  PushToStack<uint16_t>(memory, state, TruncTo<uint16_t>(state.rflag.flat));
  return memory;
}

#if 32 == ADDRESS_SIZE_BITS
DEF_SEM(DoPUSHFD) {
  SerializeFlags(state);
  PushToStack<uint32_t>(memory, state, TruncTo<uint32_t>(state.rflag.flat));
  return memory;
}
#else
DEF_SEM(DoPUSHFQ) {
  SerializeFlags(state);
  PushToStack<uint64_t>(memory, state, state.rflag.flat);
  return memory;
}
#endif  // 32 == ADDRESS_SIZE_BITS

}  // namespace

DEF_ISEL(PUSH_GPRv_FFr6_16) = PUSH<R16>;
DEF_ISEL_RI32or64(PUSH_GPRv_FFr6, PUSH);

DEF_ISEL(PUSH_GPRv_50_16) = PUSH<R16>;
DEF_ISEL_RI32or64(PUSH_GPRv_50, PUSH);

DEF_ISEL(PUSH_IMMz_16) = PUSH<I16>;
DEF_ISEL_RI32or64(PUSH_IMMz, PUSH);

DEF_ISEL(PUSH_IMMb_16) = PUSH<I16>;
DEF_ISEL_RI32or64(PUSH_IMMb, PUSH);

DEF_ISEL(PUSH_MEMv_16) = PUSH<M16>;
DEF_ISEL_M32or64(PUSH_MEMv, PUSH);


#if 32 == ADDRESS_SIZE_BITS
DEF_ISEL(PUSHA_16) = DoPUSHA;
DEF_ISEL(PUSHAD_32) = DoPUSHAD;
#endif

DEF_ISEL(PUSHF) = DoPUSHF;

#if 32 == ADDRESS_SIZE_BITS
DEF_ISEL(PUSHFD) = DoPUSHFD;
#else
DEF_ISEL(PUSHFQ) = DoPUSHFQ;
#endif  // 32 == ADDRESS_SIZE_BITS

/*
759 PUSH PUSH_ES PUSH BASE I86 ATTRIBUTES: FIXED_BASE0 SCALABLE STACKPUSH0
760 PUSH PUSH_CS PUSH BASE I86 ATTRIBUTES: FIXED_BASE0 SCALABLE STACKPUSH0
761 PUSH PUSH_SS PUSH BASE I86 ATTRIBUTES: FIXED_BASE0 SCALABLE STACKPUSH0
762 PUSH PUSH_DS PUSH BASE I86 ATTRIBUTES: FIXED_BASE0 SCALABLE STACKPUSH0
766 PUSH PUSH_FS PUSH BASE I86 ATTRIBUTES: FIXED_BASE0 SCALABLE STACKPUSH0
767 PUSH PUSH_GS PUSH BASE I86 ATTRIBUTES: FIXED_BASE0 SCALABLE STACKPUSH0

 */
