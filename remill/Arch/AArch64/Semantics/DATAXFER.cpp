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

DEF_SEM(StorePairUpdateIndex32, R32 src1, R32 src2, MV64W dst_mem,
                                R64W dst_reg, ADDR next_addr) {
  uint32v2_t vec = {};
  vec = UInsertV32(vec, 0, Read(src1));
  vec = UInsertV32(vec, 1, Read(src2));
  UWriteV32(dst_mem, vec);
  Write(dst_reg, Read(next_addr));
  return memory;
}

DEF_SEM(StorePairUpdateIndex64, R64 src1, R64 src2, MV128W dst_mem,
                                R64W dst_reg, ADDR next_addr) {
  uint64v2_t vec = {};
  vec = UInsertV64(vec, 0, Read(src1));
  vec = UInsertV64(vec, 1, Read(src2));
  UWriteV64(dst_mem, vec);
  Write(dst_reg, Read(next_addr));
  return memory;
}

}  // namespace

DEF_ISEL(STP_32_LDSTPAIR_PRE) = StorePairUpdateIndex32;
DEF_ISEL(STP_32_LDSTPAIR_POS) = StorePairUpdateIndex32;

DEF_ISEL(STP_64_LDSTPAIR_PRE) = StorePairUpdateIndex64;
DEF_ISEL(STP_64_LDSTPAIR_POS) = StorePairUpdateIndex64;

namespace {

DEF_SEM(LoadPairUpdateIndex32, R32W dst1, R32W dst2, MV64 src_mem,
                               R64W dst_reg, ADDR next_addr) {
  auto vec = UReadV32(src_mem);
  WriteZExt(dst1, UExtractV32(vec, 0));
  WriteZExt(dst2, UExtractV32(vec, 1));
  Write(dst_reg, Read(next_addr));
  return memory;
}

DEF_SEM(LoadPairUpdateIndex64, R64W dst1, R64W dst2, MV128 src_mem,
                               R64W dst_reg, ADDR next_addr) {
  auto vec = UReadV64(src_mem);
  Write(dst1, UExtractV64(vec, 0));
  Write(dst2, UExtractV64(vec, 1));
  Write(dst_reg, Read(next_addr));
  return memory;
}

}  // namespace

DEF_ISEL(LDP_32_LDSTPAIR_PRE) = LoadPairUpdateIndex32;
DEF_ISEL(LDP_32_LDSTPAIR_POST) = LoadPairUpdateIndex32;

DEF_ISEL(LDP_64_LDSTPAIR_PRE) = LoadPairUpdateIndex64;
DEF_ISEL(LDP_64_LDSTPAIR_POST) = LoadPairUpdateIndex64;

namespace {

DEF_SEM(LoadPair32, R32W dst1, R32W dst2, MV64 src_mem) {
  auto vec = UReadV32(src_mem);
  WriteZExt(dst1, UExtractV32(vec, 0));
  WriteZExt(dst2, UExtractV32(vec, 1));
  return memory;
}

DEF_SEM(LoadPair64, R64W dst1, R64W dst2, MV128 src_mem) {
  auto vec = UReadV64(src_mem);
  Write(dst1, UExtractV64(vec, 0));
  Write(dst2, UExtractV64(vec, 1));
  return memory;
}

}  // namespace

DEF_ISEL(LDP_32_LDSTPAIR_OFF) = LoadPair32;
DEF_ISEL(LDP_64_LDSTPAIR_OFF) = LoadPair64;

namespace {

template <typename T>
DEF_SEM(Load, R64W dst, T src) {
  WriteZExt(dst, Read(src));
  return memory;
}

}  // namespace

DEF_ISEL(LDR_32_LDST_POS) = Load<M32>;
DEF_ISEL(LDR_64_LDST_POS) = Load<M64>;

DEF_ISEL(LDR_32_LOADLIT) = Load<M32>;
DEF_ISEL(LDR_64_LOADLIT) = Load<M64>;


