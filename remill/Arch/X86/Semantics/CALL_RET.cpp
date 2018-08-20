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
DEF_SEM(CALL, T target_pc, PC return_pc) {
  addr_t next_sp = USub(REG_XSP, ADDRESS_SIZE_BYTES);
  Write(WritePtr<addr_t>(next_sp _IF_32BIT(REG_SS_BASE)), Read(return_pc));
  Write(REG_XSP, next_sp);
  Write(REG_PC, ZExtTo<addr_t>(Read(target_pc)));
  return memory;
}

DEF_SEM(RET_IMM, I16 bytes) {
  Write(REG_PC, Read(ReadPtr<addr_t>(REG_XSP _IF_32BIT(REG_SS_BASE))));
  Write(REG_XSP,
        UAdd(UAdd(REG_XSP, ZExtTo<addr_t>(Read(bytes))), ADDRESS_SIZE_BYTES));
  return memory;
}

DEF_SEM(RET) {
  Write(REG_PC, Read(ReadPtr<addr_t>(REG_XSP _IF_32BIT(REG_SS_BASE))));
  Write(REG_XSP, UAdd(REG_XSP, ADDRESS_SIZE_BYTES));
  return memory;
}

}  // namespace

DEF_ISEL_32or64(CALL_NEAR_RELBRd, CALL<PC>);
DEF_ISEL_32or64(CALL_NEAR_RELBRz, CALL<PC>);

IF_32BIT( DEF_ISEL(CALL_NEAR_MEMv_16) = CALL<M16>; )
IF_32BIT( DEF_ISEL(CALL_NEAR_MEMv_32) = CALL<M32>; )
IF_64BIT( DEF_ISEL(CALL_NEAR_MEMv_64) = CALL<M64>; )

IF_32BIT( DEF_ISEL(CALL_NEAR_GPRv_16) = CALL<R16>; )
IF_32BIT( DEF_ISEL(CALL_NEAR_GPRv_32) = CALL<R32>; )
IF_64BIT( DEF_ISEL(CALL_NEAR_GPRv_64) = CALL<R64>; )

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

#if ADDRESS_SIZE_BITS == 32
namespace {
DEF_SEM(IRETD) {
  auto new_eip = PopFromStack<uint32_t>(memory, state);
  auto new_cs = static_cast<uint16_t>(PopFromStack<uint32_t>(memory, state));
  auto temp_eflags = PopFromStack<uint32_t>(memory, state);
  Flags f = {};
  f.flat = (temp_eflags & 0x257FD5U) | 0x1A0000U;
  Write(REG_PC, new_eip);
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
}

DEF_ISEL(IRETD_32) = IRETD;
#endif
