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

// Note: Special handling of `dst` when it has the form `POP [xSP + ...]`
//       is handled in the arch-specific instruction operand lifter.
//
//       The case of `POP xSP` is correctly handled without special casing.
template <typename D>
DEF_SEM(POP, D dst) {
  addr_t op_size = ZExtTo<D>(ByteSizeOf(dst));
  addr_t old_xsp = Read(REG_XSP);
  addr_t new_xsp = UAdd(old_xsp, op_size);
  Write(REG_XSP, new_xsp);
  WriteZExt(dst, Read(ReadPtr<D>(old_xsp _IF_32BIT(REG_SS_BASE))));
  return memory;
}

#if 32 == ADDRESS_SIZE_BITS
DEF_SEM(DoPOPA) {
  Write(REG_DI, PopFromStack<uint16_t>(memory, state));
  Write(REG_SI, PopFromStack<uint16_t>(memory, state));
  Write(REG_BP, PopFromStack<uint16_t>(memory, state));
  (void) PopFromStack<uint16_t>(memory, state);  // Ignore SP.
  Write(REG_BX, PopFromStack<uint16_t>(memory, state));
  Write(REG_DX, PopFromStack<uint16_t>(memory, state));
  Write(REG_CX, PopFromStack<uint16_t>(memory, state));
  Write(REG_AX, PopFromStack<uint16_t>(memory, state));
  return memory;
}

DEF_SEM(DoPOPAD) {
  Write(REG_EDI, PopFromStack<uint32_t>(memory, state));
  Write(REG_ESI, PopFromStack<uint32_t>(memory, state));
  Write(REG_EBP, PopFromStack<uint32_t>(memory, state));
  (void) PopFromStack<uint32_t>(memory, state);  // Ignore ESP.
  Write(REG_EBX, PopFromStack<uint32_t>(memory, state));
  Write(REG_EDX, PopFromStack<uint32_t>(memory, state));
  Write(REG_ECX, PopFromStack<uint32_t>(memory, state));
  Write(REG_EAX, PopFromStack<uint32_t>(memory, state));
  return memory;
}
#endif

#if 32 == ADDRESS_SIZE_BITS
DEF_SEM(DoPOPFD) {
  Flags f;
  f.flat = ZExt(PopFromStack<uint32_t>(memory, state));
  state.aflag.af = f.af;
  state.aflag.cf = f.cf;
  state.aflag.df = f.df;
  state.aflag.of = f.of;
  state.aflag.pf = f.pf;
  state.aflag.sf = f.sf;
  state.aflag.zf = f.zf;

  state.rflag.id = f.id;

  //  state.rflag.ac = f.ac;
  //  state.rflag.tf = f.tf;
  //  state.rflag.nt = f.nt;
  return memory;
}
#else

// TODO(pag): Privileged mode flags.
DEF_SEM(DoPOPFQ) {
  Flags f;
  f.flat = PopFromStack<uint64_t>(memory, state);
  state.aflag.af = f.af;
  state.aflag.cf = f.cf;
  state.aflag.df = f.df;
  state.aflag.of = f.of;
  state.aflag.pf = f.pf;
  state.aflag.sf = f.sf;
  state.aflag.zf = f.zf;

  state.rflag.id = f.id;

  //  state.rflag.ac = f.ac;
  //  state.rflag.tf = f.tf;
  //  state.rflag.nt = f.nt;
  return memory;
}
#endif  // 32 == ADDRESS_SIZE_BITS

// TODO(pag): Make behaviour conditional on `rflag.cpl`.
DEF_SEM(DoPOPF) {
  Flags f;
  f.flat = ZExt(ZExt(PopFromStack<uint16_t>(memory, state)));
  state.aflag.af = f.af;
  state.aflag.cf = f.cf;
  state.aflag.df = f.df;
  state.aflag.of = f.of;
  state.aflag.pf = f.pf;
  state.aflag.sf = f.sf;
  state.aflag.zf = f.zf;
  return memory;
}
}  // namespace

DEF_ISEL(POP_GPRv_8F_16) = POP<R16W>;
DEF_ISEL_R32or64W(POP_GPRv_8F, POP);

DEF_ISEL(POP_GPRv_51_16) = POP<R16W>;
DEF_ISEL(POP_GPRv_58_16) = POP<R16W>;
DEF_ISEL_R32or64W(POP_GPRv_51, POP);
DEF_ISEL_R32or64W(POP_GPRv_58, POP);

DEF_ISEL(POP_MEMv_16) = POP<M16W>;
DEF_ISEL_M32or64W(POP_MEMv, POP);

#if 32 == ADDRESS_SIZE_BITS
DEF_ISEL(POPA_32) = DoPOPA;
DEF_ISEL(POPAD_32) = DoPOPAD;
#endif

DEF_ISEL(POPF) = DoPOPF;

#if 32 == ADDRESS_SIZE_BITS
DEF_ISEL(POPFD) = DoPOPFD;
#else
DEF_ISEL(POPFQ) = DoPOPFQ;
#endif  // 32 == ADDRESS_SIZE_BITS

namespace {

template <typename T>
DEF_SEM(POP_ES, R16W dst) {
  addr_t addr_size = static_cast<addr_t>(sizeof(T));
  addr_t stack_ptr = Read(REG_XSP);
  Write(dst, TruncTo<uint16_t>(Read(ReadPtr<T>(stack_ptr))));
  Write(REG_XSP, UAdd(stack_ptr, addr_size));
  return __remill_sync_hyper_call(state, memory,
                                  SyncHyperCall::kX86SetSegmentES);
}

template <typename T>
DEF_SEM(POP_SS, R16W dst) {
  addr_t addr_size = static_cast<addr_t>(sizeof(T));
  addr_t stack_ptr = Read(REG_XSP);
  Write(dst, TruncTo<uint16_t>(Read(ReadPtr<T>(stack_ptr))));
  Write(REG_XSP, UAdd(stack_ptr, addr_size));
  return __remill_sync_hyper_call(state, memory,
                                  SyncHyperCall::kX86SetSegmentSS);
}

template <typename T>
DEF_SEM(POP_DS, R16W dst) {
  addr_t addr_size = static_cast<addr_t>(sizeof(T));
  addr_t stack_ptr = Read(REG_XSP);
  Write(dst, TruncTo<uint16_t>(Read(ReadPtr<T>(stack_ptr))));
  Write(REG_XSP, UAdd(stack_ptr, addr_size));
  return __remill_sync_hyper_call(state, memory,
                                  SyncHyperCall::kX86SetSegmentDS);
}

template <typename T>
DEF_SEM(POP_FS, R16W dst) {
  addr_t addr_size = static_cast<addr_t>(sizeof(T));
  addr_t stack_ptr = Read(REG_XSP);
  Write(dst, TruncTo<uint16_t>(Read(ReadPtr<T>(stack_ptr))));
  Write(REG_XSP, UAdd(stack_ptr, addr_size));
  return __remill_sync_hyper_call(state, memory,
                                  SyncHyperCall::kX86SetSegmentFS);
}

template <typename T>
DEF_SEM(POP_GS, R16W dst) {
  addr_t addr_size = static_cast<addr_t>(sizeof(T));
  addr_t stack_ptr = Read(REG_XSP);
  Write(dst, TruncTo<uint16_t>(Read(ReadPtr<T>(stack_ptr))));
  Write(REG_XSP, UAdd(stack_ptr, addr_size));
  return __remill_sync_hyper_call(state, memory,
                                  SyncHyperCall::kX86SetSegmentGS);
}

}  // namespace

#if 32 == ADDRESS_SIZE_BITS
DEF_ISEL(POP_ES_16) = POP_ES<uint16_t>;
DEF_ISEL(POP_ES_32) = POP_ES<uint32_t>;

DEF_ISEL(POP_SS_16) = POP_SS<uint16_t>;
DEF_ISEL(POP_SS_32) = POP_SS<uint32_t>;

DEF_ISEL(POP_DS_16) = POP_DS<uint16_t>;
DEF_ISEL(POP_DS_32) = POP_DS<uint32_t>;

DEF_ISEL(POP_FS_16) = POP_FS<uint16_t>;
DEF_ISEL(POP_FS_32) = POP_FS<uint32_t>;

DEF_ISEL(POP_GS_16) = POP_GS<uint16_t>;
DEF_ISEL(POP_GS_32) = POP_GS<uint32_t>;
#else
DEF_ISEL(POP_ES_16) = POP_ES<uint16_t>;
DEF_ISEL(POP_ES_64) = POP_ES<uint64_t>;

DEF_ISEL(POP_SS_16) = POP_SS<uint16_t>;
DEF_ISEL(POP_SS_64) = POP_SS<uint64_t>;

DEF_ISEL(POP_DS_16) = POP_DS<uint16_t>;
DEF_ISEL(POP_DS_64) = POP_DS<uint64_t>;

DEF_ISEL(POP_FS_16) = POP_FS<uint16_t>;
DEF_ISEL(POP_FS_64) = POP_FS<uint64_t>;

DEF_ISEL(POP_GS_16) = POP_GS<uint16_t>;
DEF_ISEL(POP_GS_64) = POP_GS<uint64_t>;
#endif  // 64 == ADDRESS_SIZE_BITS
