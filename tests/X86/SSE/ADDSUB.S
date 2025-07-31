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

#define TEST_INPUT_ADDSUB \
    0.0, 0.0, \
    0.0, 100000.5, \
    100000.5, 100000.5

TEST_BEGIN_64(ADDSUBPSv128v128, 2)
TEST_INPUTS(TEST_INPUT_ADDSUB)
    push ARG1_64
    push ARG1_64
    movupd xmm1, [rsp]
    push ARG2_64
    push ARG2_64
    movupd xmm2, [rsp]
    addsubps xmm2, xmm1
TEST_END_64

TEST_BEGIN_64(ADDSUBPSv128m128, 2)
TEST_INPUTS(TEST_INPUT_ADDSUB)
    push ARG1_64
    push ARG1_64
    movupd xmm1, [rsp]
    push ARG2_64
    push ARG2_64
    addsubps xmm2, [rsp]
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VADDSUBPSv128v128v128, 2)
TEST_INPUTS(TEST_INPUT_ADDSUB)
    push ARG1_64
    push ARG1_64
    movupd xmm1, [rsp]
    push ARG2_64
    push ARG2_64
    movupd xmm2, [rsp]
    vaddsubps xmm0, xmm2, xmm1
TEST_END_64

TEST_BEGIN_64(VADDSUBPSv128v128m128, 2)
TEST_INPUTS(TEST_INPUT_ADDSUB)
    push ARG1_64
    push ARG1_64
    movupd xmm1, [rsp]
    push ARG2_64
    push ARG2_64
    vaddsubps xmm0, xmm2, [rsp]
TEST_END_64

TEST_BEGIN_64(VADDSUBPSv256v256v256, 2)
TEST_INPUTS(TEST_INPUT_ADDSUB)
    push ARG1_64
    push 0
    push 0
    push ARG1_64
    vmovupd xmm1, [rsp]
    push ARG2_64
    push ARG2_64
    push ARG2_64
    push ARG2_64
    vmovupd xmm2, [rsp]
    vaddsubps xmm0, xmm2, xmm1
TEST_END_64

TEST_BEGIN_64(VADDSUBPSv256v256m256, 2)
TEST_INPUTS(TEST_INPUT_ADDSUB)
    push ARG1_64
    push 0
    push 0
    push ARG1_64
    vmovupd xmm1, [rsp]
    push ARG2_64
    push 0
    push 0
    push ARG2_64
    vaddsubps xmm0, xmm2, [rsp]
TEST_END_64

#endif // HAS_FEATURE_AVX

TEST_BEGIN_64(ADDSUBPDv128v128, 2)
TEST_INPUTS(TEST_INPUT_ADDSUB)
    push ARG1_64
    push ARG1_64
    movupd xmm1, [rsp]
    push ARG2_64
    push ARG2_64
    movupd xmm2, [rsp]
    addsubps xmm2, xmm1
TEST_END_64

TEST_BEGIN_64(ADDSUBPDv128m128, 2)
TEST_INPUTS(TEST_INPUT_ADDSUB)
    push ARG1_64
    push ARG1_64
    movupd xmm1, [rsp]
    push ARG2_64
    push ARG2_64
    addsubps xmm2, [rsp]
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VADDSUBPDv128v128v128, 2)
TEST_INPUTS(TEST_INPUT_ADDSUB)
    push ARG1_64
    push ARG1_64
    movupd xmm1, [rsp]
    push ARG2_64
    push ARG2_64
    movupd xmm2, [rsp]
    vaddsubpd xmm0, xmm2, xmm1
TEST_END_64

TEST_BEGIN_64(VADDSUBPDv128v128m128, 2)
TEST_INPUTS(TEST_INPUT_ADDSUB)
    push ARG1_64
    push ARG1_64
    movupd xmm1, [rsp]
    push ARG2_64
    push ARG2_64
    vaddsubpd xmm0, xmm2, [rsp]
TEST_END_64

TEST_BEGIN_64(VADDSUBPDv256v256v256, 2)
TEST_INPUTS(TEST_INPUT_ADDSUB)
    push ARG1_64
    push 0
    push 0
    push ARG1_64
    vmovupd xmm1, [rsp]
    push ARG2_64
    push ARG2_64
    push ARG2_64
    push ARG2_64
    vmovupd xmm2, [rsp]
    vaddsubpd xmm0, xmm2, xmm1
TEST_END_64

TEST_BEGIN_64(VADDSUBPDv256v256m256, 2)
TEST_INPUTS(TEST_INPUT_ADDSUB)
    push ARG1_64
    push 0
    push 0
    push ARG1_64
    vmovupd xmm1, [rsp]
    push ARG2_64
    push 0
    push 0
    push ARG2_64
    vaddsubpd xmm0, xmm2, [rsp]
TEST_END_64

#endif // HAS_FEATURE_AVX