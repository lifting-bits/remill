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

template <typename T>
DEF_SEM(CALL, T target_pc, IF_32BIT_ELSE(R32W, R64W) pc_dst, PC return_pc,
        IF_32BIT_ELSE(R32W, R64W) return_pc_dst) {
  addr_t next_sp = USub(REG_XSP, ADDRESS_SIZE_BYTES);
  const auto new_pc = ZExtTo<addr_t>(Read(target_pc));
  Write(WritePtr<addr_t>(next_sp _IF_32BIT(REG_SS_BASE)), Read(return_pc));
  Write(REG_XSP, next_sp);
  Write(REG_PC, new_pc);
  Write(pc_dst, new_pc);
  Write(return_pc_dst, Read(return_pc));
  return memory;
}

DEF_SEM(RET_IMM, I16 bytes, IF_32BIT_ELSE(R32W, R64W) pc_dst) {
  const auto new_pc = Read(ReadPtr<addr_t>(REG_XSP _IF_32BIT(REG_SS_BASE)));
  Write(REG_PC, new_pc);
  Write(pc_dst, new_pc);
  Write(REG_XSP,
        UAdd(UAdd(REG_XSP, ZExtTo<addr_t>(Read(bytes))), ADDRESS_SIZE_BYTES));
  return memory;
}

DEF_SEM(RET, IF_32BIT_ELSE(R32W, R64W) pc_dst) {
  const auto new_pc = Read(ReadPtr<addr_t>(REG_XSP _IF_32BIT(REG_SS_BASE)));
  Write(REG_PC, new_pc);
  Write(pc_dst, new_pc);
  Write(REG_XSP, UAdd(REG_XSP, ADDRESS_SIZE_BYTES));
  return memory;
}

}  // namespace

DEF_ISEL_32or64(CALL_NEAR_RELBRd, CALL<PC>);
DEF_ISEL_32or64(CALL_NEAR_RELBRz, CALL<PC>);

IF_32BIT(DEF_ISEL(CALL_NEAR_MEMv_16) = CALL<M16>;)
IF_32BIT(DEF_ISEL(CALL_NEAR_MEMv_32) = CALL<M32>;)
IF_64BIT(DEF_ISEL(CALL_NEAR_MEMv_64) = CALL<M64>;)

IF_32BIT(DEF_ISEL(CALL_NEAR_GPRv_16) = CALL<R16>;)
IF_32BIT(DEF_ISEL(CALL_NEAR_GPRv_32) = CALL<R32>;)
IF_64BIT(DEF_ISEL(CALL_NEAR_GPRv_64) = CALL<R64>;)

/*
352 CALL_FAR CALL_FAR_MEMp2 CALL BASE I86 ATTRIBUTES: FAR_XFER FIXED_BASE1 NOTSX SCALABLE STACKPUSH1
353 CALL_FAR CALL_FAR_PTRp_IMMw CALL BASE I86 ATTRIBUTES: FAR_XFER FIXED_BASE0 NOTSX SCALABLE STACKPUSH0

*/

DEF_ISEL_32or64(RET_NEAR_IMMw, RET_IMM);
DEF_ISEL_32or64(RET_NEAR, RET);

/*
1073 RET_FAR RET_FAR_IMMw RET BASE I86 ATTRIBUTES: FAR_XFER FIXED_BASE0 NOTSX SCALABLE STACKPOP0
1074 RET_FAR RET_FAR RET BASE I86 ATTRIBUTES: FAR_XFER FIXED_BASE0 NOTSX SCALABLE STACKPOP0
1666 IRETQ IRETQ RET LONGMODE LONGMODE ATTRIBUTES: FIXED_BASE0 NOTSX SCALABLE STACKPOP0
1784 IRET IRET RET BASE I86 ATTRIBUTES: FIXED_BASE0 NOTSX SCALABLE STACKPOP0
728 IRETD IRETD RET BASE I386 ATTRIBUTES: FIXED_BASE0 NOTSX SCALABLE STACKPOP0
*/

namespace {
#if ADDRESS_SIZE_BITS == 32
DEF_SEM(IRETD, IF_32BIT_ELSE(R32W, R64W) pc_dst) {
  auto new_eip = PopFromStack<uint32_t>(memory, state);
  auto new_cs = static_cast<uint16_t>(PopFromStack<uint32_t>(memory, state));
  auto temp_eflags = PopFromStack<uint32_t>(memory, state);
  Flags f = {};
  f.flat = (temp_eflags & 0x257FD5U) | 0x1A0000U;
  Write(REG_PC, new_eip);
  Write(pc_dst, new_eip);
  Write(REG_CS.flat, new_cs);
  state.rflag = f;
  state.aflag.af = f.af;
  state.aflag.cf = f.cf;
  state.aflag.df = f.df;
  state.aflag.of = f.of;
  state.aflag.pf = f.pf;
  state.aflag.sf = f.sf;
  state.aflag.zf = f.zf;
  state.hyper_call = AsyncHyperCall::kX86IRet;
  return memory;
}

DEF_ISEL(IRETD_32) = IRETD;

#elif ADDRESS_SIZE_BITS == 64
DEF_SEM(IRETQ, IF_32BIT_ELSE(R32W, R64W) pc_dst) {
  auto new_rip = PopFromStack<uint64_t>(memory, state);
  auto new_cs = static_cast<uint16_t>(PopFromStack<uint64_t>(memory, state));
  auto temp_rflags = PopFromStack<uint64_t>(memory, state);
  Flags f = {};
  f.flat = temp_rflags;
  Write(REG_PC, new_rip);
  Write(pc_dst, new_rip);
  Write(REG_CS.flat, new_cs);
  state.rflag = f;
  state.aflag.af = f.af;
  state.aflag.cf = f.cf;
  state.aflag.df = f.df;
  state.aflag.of = f.of;
  state.aflag.pf = f.pf;
  state.aflag.sf = f.sf;
  state.aflag.zf = f.zf;
  state.hyper_call = AsyncHyperCall::kX86IRet;

  // TODO(tathanhdinh): Update the hidden part (segment shadow) of CS,
  //                    see Issue #334

  auto new_rsp = PopFromStack<uint64_t>(memory, state);
  auto new_ss = static_cast<uint16_t>(PopFromStack<uint64_t>(memory, state));
  Write(REG_RSP, new_rsp);
  Write(REG_SS.flat, new_ss);

  // TODO(tathanhdinh): Update the hidden part (segment shadow) of SS,
  //                    see Issue #334

  return memory;
}

DEF_ISEL(IRETQ_64) = IRETQ;
#endif
}  // namespace
