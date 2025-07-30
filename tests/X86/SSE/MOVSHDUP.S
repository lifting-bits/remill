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

 #define TEST_INPUT_DUP \
    0xaabbccddeeff0099, 0x1122334455667788 

TEST_BEGIN_64(MOVSHDUPv128v128, 2)
TEST_INPUTS(TEST_INPUT_DUP)
    push ARG1_64
    push ARG2_64
    movdqu xmm1, [rsp]
    movshdup xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(MOVSHDUPv128m128, 2)
TEST_INPUTS(TEST_INPUT_DUP)
    push ARG1_64
    push ARG2_64
    movshdup xmm0, [rsp]
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VMOVSHDUPv128v128, 2)
TEST_INPUTS(TEST_INPUT_DUP)
    push ARG1_64
    push ARG2_64
    vmovdqu xmm1, [rsp]
    vmovshdup xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(VMOVSHDUPv128m128, 2)
TEST_INPUTS(TEST_INPUT_DUP)
    push ARG1_64
    push ARG2_64
    vmovshdup xmm0, [rsp]
TEST_END_64

TEST_BEGIN_64(VMOVSHDUPv256v256, 2)
TEST_INPUTS(TEST_INPUT_DUP)
    push ARG1_64
    push ARG2_64
    push ARG1_64
    push ARG2_64
    vmovdqu ymm1, [rsp]
    vmovshdup ymm0, ymm1
TEST_END_64

TEST_BEGIN_64(VMOVSHDUPv256m256, 2)
TEST_INPUTS(TEST_INPUT_DUP)
    push ARG1_64
    push ARG2_64
    push ARG1_64
    push ARG2_64
    vmovshdup ymm0, [rsp]
TEST_END_64

#endif
