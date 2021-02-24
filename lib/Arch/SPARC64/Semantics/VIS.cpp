/*
 * Copyright (c) 2019 Trail of Bits, Inc.
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

// TODO(akshay) Discuss the VIS instructions with pag
// This is an alternative to SIMD instructions which reuses
// the floating point unit to perform partitioned Arithematic
// and logical operations
namespace {

template <typename S1, typename S2, typename D>
DEF_SEM(PACK_ORS, S1 src1, S2 src2, D dst) {
  UWriteV32(dst, UOrV32(UReadV32(src1), UReadV32(src2)));
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(PACK_ORD, S1 src1, S2 src2, D dst) {
  UWriteV64(dst, UOrV64(UReadV64(src1), UReadV64(src2)));
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(PACK_XORS, S1 src1, S2 src2, D dst) {
  UWriteV32(dst, UXorV32(UReadV32(src1), UReadV32(src2)));
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(PACK_XORD, S1 src1, S2 src2, D dst) {
  UWriteV64(dst, UXorV64(UReadV64(src1), UReadV64(src2)));
  return memory;
}


// TODO(akshayk) We need to check for the 32 bit addressing
// in PSTATE.am
DEF_SEM(EDGE8CC, R64 src1, R64 src2, R64W dst) {
  auto rs1 = Read(src1);
  auto rs2 = Read(src2);
  auto imask = Literal<I64>(0x7);
  auto shift = Literal<I64>(3);
  auto omask = Literal<I8>(0xff);

  // l1 = rs1 & 0x7 rs[3:0]
  auto l1 = UAnd(rs1, imask);
  auto rs1_shifted = UShr(rs1, shift);

  // l2 = rs2 & 0x7 rs[3:0]
  auto l2 = UAnd(rs2, imask);
  auto rs2_shifted = UShr(rs2, shift);
  auto left_edge = UShr(omask, decltype(omask)(l1));
  auto right_edge = UShl(omask, decltype(omask)(USub(imask, l2)));
  auto value = Select(UCmpEq(rs1_shifted, rs2_shifted), left_edge,
                      UAnd(right_edge, left_edge));
  auto diff = USub(rs1, rs2);
  WriteICCFlagsAddSub<tag_sub>(state, Literal<uint32_t>(rs1),
                               Literal<uint32_t>(rs2), Literal<uint32_t>(diff));
  WriteXCCFlagsAddSub<tag_sub>(state, rs1, rs2, diff);
  WriteZExt(dst, value);
  return memory;
}


}  // namespace

DEF_ISEL(FORS) = PACK_ORS<V32W, V32W, V32W>;
DEF_ISEL(FORD) = PACK_ORD<V64W, V64W, V64W>;
DEF_ISEL(FXORS) = PACK_XORS<V32W, V32W, V32W>;
DEF_ISEL(FXORD) = PACK_XORD<V64W, V64W, V64W>;


DEF_ISEL(EDGE8cc) = EDGE8CC;

namespace {

DEF_SEM(IMPDEP1, I32 opf) {
  HYPER_CALL_VECTOR = Literal<decltype(state.hyper_call_vector)>(Read(opf));
  return __remill_sync_hyper_call(
      state, memory,
      SyncHyperCall::IF_32BIT_ELSE(kSPARC32EmulateInstruction,
                                   kSPARC64EmulateInstruction));
}

DEF_SEM(IMPDEP2, I32 opf) {
  HYPER_CALL_VECTOR = Literal<decltype(state.hyper_call_vector)>(Read(opf));
  return __remill_sync_hyper_call(
      state, memory,
      SyncHyperCall::IF_32BIT_ELSE(kSPARC32EmulateInstruction,
                                   kSPARC64EmulateInstruction));
}

}  // namespace

DEF_ISEL(IMPDEP1) = IMPDEP1;
DEF_ISEL(IMPDEP2) = IMPDEP2;
