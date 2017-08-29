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

template <typename T>
DEF_SEM(JMP, T target_pc) {
  WriteZExt(REG_PC, Read(target_pc));
  return memory;
}

}  // namespace

DEF_ISEL(JMP_RELBRd) = JMP<PC>;
DEF_ISEL(JMP_RELBRb) = JMP<PC>;
DEF_ISEL_32or64(JMP_RELBRz, JMP<PC>);

#if 64 == ADDRESS_SIZE_BITS
DEF_ISEL(JMP_MEMv_64) = JMP<M64>;
DEF_ISEL(JMP_GPRv_64) = JMP<R64>;
#else
DEF_ISEL(JMP_MEMv_16) = JMP<M16>;
DEF_ISEL(JMP_MEMv_32) = JMP<M32>;

DEF_ISEL(JMP_GPRv_16) = JMP<R16>;
DEF_ISEL(JMP_GPRv_32) = JMP<R32>;
#endif

/*

1807 JMP_FAR JMP_FAR_MEMp2 UNCOND_BR BASE I86 ATTRIBUTES: FAR_XFER NOTSX SCALABLE
1808 JMP_FAR JMP_FAR_PTRp_IMMw UNCOND_BR BASE I86 ATTRIBUTES: FAR_XFER NOTSX SCALABLE
 */
