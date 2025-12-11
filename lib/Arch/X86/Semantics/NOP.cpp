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

template <typename... Types>
DEF_SEM(NOP_IMPL, Types...) {
  return memory;
}

}  // namespace

DEF_ISEL_Rn(NOP_GPRv_0F1F, NOP_IMPL);
DEF_ISEL_Rn(NOP_GPRv_0F18r0, NOP_IMPL);
DEF_ISEL_Rn(NOP_GPRv_0F18r1, NOP_IMPL);
DEF_ISEL_Rn(NOP_GPRv_0F18r2, NOP_IMPL);
DEF_ISEL_Rn(NOP_GPRv_0F18r3, NOP_IMPL);
DEF_ISEL_Rn(NOP_GPRv_0F18r4, NOP_IMPL);
DEF_ISEL_Rn(NOP_GPRv_0F18r5, NOP_IMPL);
DEF_ISEL_Rn(NOP_GPRv_0F18r6, NOP_IMPL);
DEF_ISEL_Rn(NOP_GPRv_0F18r7, NOP_IMPL);

DEF_ISEL_Rn_Rn(NOP_GPRv_GPRv_0F19, NOP_IMPL);
DEF_ISEL_Rn_Rn(NOP_GPRv_GPRv_0F1C, NOP_IMPL);
DEF_ISEL_Rn_Rn(NOP_GPRv_GPRv_0F1D, NOP_IMPL);
DEF_ISEL_Rn_Rn(NOP_GPRv_GPRv_0F1E, NOP_IMPL);
DEF_ISEL_Rn_Rn(NOP_GPRv_GPRv_0F1F, NOP_IMPL);

DEF_ISEL_Mn(NOP_MEMv_0F1F, NOP_IMPL);
DEF_ISEL_Mn(NOP_MEMv_0F18r4, NOP_IMPL);
DEF_ISEL_Mn(NOP_MEMv_0F18r5, NOP_IMPL);
DEF_ISEL_Mn(NOP_MEMv_0F18r6, NOP_IMPL);
DEF_ISEL_Mn(NOP_MEMv_0F18r7, NOP_IMPL);

DEF_ISEL_Mn_Rn(NOP_MEMv_GPRv_0F19, NOP_IMPL);
DEF_ISEL_Mn_Rn(NOP_MEMv_GPRv_0F1C, NOP_IMPL);
DEF_ISEL_Mn_Rn(NOP_MEMv_GPRv_0F1D, NOP_IMPL);
DEF_ISEL_Mn_Rn(NOP_MEMv_GPRv_0F1E, NOP_IMPL);
DEF_ISEL_Mn_Rn(NOP_MEMv_GPRv_0F1F, NOP_IMPL);

DEF_ISEL(NOP_90) = NOP_IMPL<>;

DEF_ISEL_Rn_Rn(NOP_GPRv_GPRv_0F0D, NOP_IMPL);
DEF_ISEL_Rn_Rn(NOP_GPRv_GPRv_0F1A, NOP_IMPL);
DEF_ISEL_Rn_Rn(NOP_GPRv_GPRv_0F1B, NOP_IMPL);

DEF_ISEL_Rn_Mn(NOP_GPRv_MEMv_0F1A, NOP_IMPL);
DEF_ISEL_Rn_Mn(NOP_GPRv_MEM_0F1B, NOP_IMPL);

/*

401 FENI8087_NOP FENI8087_NOP X87_ALU X87 X87 ATTRIBUTES: NOP NOTSX
546 FSETPM287_NOP FSETPM287_NOP X87_ALU X87 X87 ATTRIBUTES: NOP NOTSX
1286 FDISI8087_NOP FDISI8087_NOP X87_ALU X87 X87 ATTRIBUTES: NOP NOTSX
 */
