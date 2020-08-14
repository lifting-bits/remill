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
DEF_SEM(JMP, T target_pc, IF_32BIT_ELSE(R32W, R64W) pc_dst) {
  auto new_pc = Read(target_pc);
  WriteZExt(REG_PC, new_pc);
  WriteZExt(pc_dst, new_pc);
  return memory;
}

template <typename T>
DEF_SEM(JMP_FAR_MEM, T target_seg_pc, IF_32BIT_ELSE(R32W, R64W) pc_dst) {
  HYPER_CALL = AsyncHyperCall::kX86JmpFar;
  uint64_t target_fword = UShr(UShl(Read(target_seg_pc), 0xf), 0xf);
  auto pc = static_cast<uint32_t>(target_fword);
  auto seg = static_cast<uint16_t>(UShr(target_fword, 32));
  WriteZExt(REG_PC, pc);
  WriteZExt(pc_dst, pc);
  Write(REG_CS.flat, seg);

  // TODO(tathanhdinh): Update the hidden part (segment shadow) of CS,
  //                    see Issue #334

  return memory;
}

template <typename S1, typename S2>
DEF_SEM(JMP_FAR_PTR, S1 src1, S2 src2, IF_32BIT_ELSE(R32W, R64W) pc_dst) {
  HYPER_CALL = AsyncHyperCall::kX86JmpFar;
  auto pc = Read(src1);
  auto seg = Read(src2);
  WriteZExt(REG_PC, pc);
  WriteZExt(pc_dst, pc);
  Write(REG_CS.flat, seg);

  // TODO(tathanhdinh): Update the hidden part (segment shadow) of CS,
  //                    see Issue #334

  return memory;
}


}  // namespace

DEF_ISEL(JMP_RELBRd) = JMP<PC>;
DEF_ISEL(JMP_RELBRb) = JMP<PC>;
DEF_ISEL_32or64(JMP_RELBRz, JMP<PC>);

#if 64 == ADDRESS_SIZE_BITS
DEF_ISEL(JMP_MEMv_64) = JMP<M64>;
DEF_ISEL(JMP_GPRv_64) = JMP<R64>;

DEF_ISEL(JMP_FAR_MEMp2_32) = JMP_FAR_MEM<M64>;
#else
DEF_ISEL(JMP_MEMv_16) = JMP<M16>;
DEF_ISEL(JMP_MEMv_32) = JMP<M32>;

DEF_ISEL(JMP_GPRv_16) = JMP<R16>;
DEF_ISEL(JMP_GPRv_32) = JMP<R32>;

DEF_ISEL(JMP_FAR_MEMp2_32) = JMP_FAR_MEM<M32>;
DEF_ISEL(JMP_FAR_PTRp_IMMw_32) = JMP_FAR_PTR<I32, I16>;
DEF_ISEL(JMP_FAR_PTRp_IMMw_16) = JMP_FAR_PTR<I16, I16>;
#endif

/*

1807 JMP_FAR JMP_FAR_MEMp2 UNCOND_BR BASE I86 ATTRIBUTES: FAR_XFER NOTSX SCALABLE
1808 JMP_FAR JMP_FAR_PTRp_IMMw UNCOND_BR BASE I86 ATTRIBUTES: FAR_XFER NOTSX SCALABLE
 */
