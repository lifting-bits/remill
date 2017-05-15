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

TEST_BEGIN_64(PMOVMSKBr32v64, 1)
TEST_INPUTS(
    0,
    0x8080808080808080,
    0xffffffffffffffff,
    0x80808080,
    0x8080808000000000,
    0x0080008000800080)

    movq mm0, ARG1_64
    pmovmskb eax, mm0
TEST_END_64

TEST_BEGIN_64(PMOVMSKBr32v128_0, 1)
TEST_INPUTS(
    0,
    0x8080808080808080,
    0xffffffffffffffff,
    0x80808080,
    0x8080808000000000,
    0x0080008000800080)

    movq xmm0, ARG1_64
    pmovmskb eax, xmm0
TEST_END_64

TEST_BEGIN_64(PMOVMSKBr32v128_4, 1)
TEST_INPUTS(
    0,
    0x8080808080808080,
    0xffffffffffffffff,
    0x80808080,
    0x8080808000000000,
    0x0080008000800080)

    movq xmm4, ARG1_64
    pmovmskb eax, xmm4
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VPMOVMSKBr32v256_0, 1)
TEST_INPUTS(
    0,
    0x8080808080808080,
    0xffffffffffffffff,
    0x80808080,
    0x8080808000000000,
    0x0080008000800080)

    vmovq xmm0, ARG1_64
    vpmovmskb eax, ymm0
TEST_END_64

TEST_BEGIN_64(VPMOVMSKBr32v256_4, 1)
TEST_INPUTS(
    0,
    0x8080808080808080,
    0xffffffffffffffff,
    0x80808080,
    0x8080808000000000,
    0x0080008000800080)

    vmovq xmm4, ARG1_64
    vpmovmskb eax, ymm4
TEST_END_64

#endif  // HAS_FEATURE_AVX
