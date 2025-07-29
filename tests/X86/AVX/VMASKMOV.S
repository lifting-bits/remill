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

#define TEST_INPUTS_MASK \
    0, 0xFFFFFFFFFFFFFFFF,  \
    0x40, 0xFFFFFFFFFFFFFFFF,  \
    0x80000000, 0xFFFFFFFFFFFFFFFF, \
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VMASKMOVPSv128v128m128, 2)
TEST_INPUTS(TEST_INPUTS_MASK)
    push ARG1_64
    push ARG1_64
    movdqu xmm1, [rsp]
    push ARG2_64
    push ARG2_64
    vmaskmovps xmm3, xmm1, xmmword ptr [rsp] 
TEST_END_64

TEST_BEGIN_64(VMASKMOVPSm128v128v128, 2)
TEST_INPUTS(TEST_INPUTS_MASK)
    push ARG1_64
    push ARG1_64
    vmovdqu xmm2, [rsp]
    lea rcx, [rsp - 16]
    vmaskmovps [rcx], xmm2, xmm0
TEST_END_64

TEST_BEGIN_64(VMASKMOVPSv256v256m256, 2)
TEST_INPUTS(TEST_INPUTS_MASK)
    push ARG1_64
    push ARG1_64
    push ARG1_64
    push ARG1_64
    vmovdqu ymm1, [rsp]
    push ARG2_64
    push ARG2_64
    push ARG2_64
    push ARG2_64
    vmaskmovps ymm0, ymm1, [rsp] 
TEST_END_64

TEST_BEGIN_64(VMASKMOVPSm256v256v256, 2)
TEST_INPUTS(TEST_INPUTS_MASK)
    push ARG1_64
    push ARG1_64
    push ARG1_64
    push ARG1_64
    vmovdqu ymm2, [rsp]
    lea rcx, [rsp - 32]
    vmaskmovps [rcx], ymm2, ymm0
TEST_END_64

TEST_BEGIN_64(VMASKMOVPDr128v128m128, 2)
TEST_INPUTS(TEST_INPUTS_MASK)
    push ARG1_64
    push ARG1_64
    vmovdqu xmm1, [rsp]
    push ARG2_64
    push ARG2_64
    vmaskmovps xmm0, xmm1, [rsp] 
TEST_END_64

TEST_BEGIN_64(VMASKMOVPDm128v128v128, 2)
TEST_INPUTS(TEST_INPUTS_MASK)
    push ARG1_64
    push ARG1_64
    vmovdqu xmm2, [rsp]
    lea rcx, [rsp - 16]
    vmaskmovps [rcx], xmm2, xmm0
TEST_END_64

TEST_BEGIN_64(VMASKMOVPDv256v256m256, 2)
TEST_INPUTS(TEST_INPUTS_MASK)
    push ARG1_64
    push ARG1_64
    push ARG1_64
    push ARG1_64
    vmovdqu ymm1, [rsp]
    push ARG2_64
    push ARG2_64
    push ARG2_64
    push ARG2_64
    vmaskmovps ymm0, ymm1, [rsp] 
TEST_END_64

TEST_BEGIN_64(VMASKMOVPDm256v256v256, 2)
TEST_INPUTS(TEST_INPUTS_MASK)
    push ARG1_64
    push ARG1_64
    push ARG1_64
    push ARG1_64
    vmovdqu ymm2, [rsp]
    lea rcx, [rsp - 32]
    vmaskmovps [rcx], ymm2, ymm0
TEST_END_64



TEST_BEGIN_64(VPMASKMOVDr128v128m128, 2)
TEST_INPUTS(TEST_INPUTS_MASK)
    push ARG1_64
    push ARG1_64
    vmovdqu xmm1, [rsp]
    push ARG2_64
    push ARG2_64
    vpmaskmovd xmm0, xmm1, [rsp] 
TEST_END_64

TEST_BEGIN_64(VPMASKMOVDm128v128v128, 2)
TEST_INPUTS(TEST_INPUTS_MASK)
    lea rcx, [rsp - 64]
    push ARG1_64
    push ARG1_64
    vmovdqu xmm2, [rsp]
    vpmaskmovd [rcx], xmm2, xmm0
TEST_END_64

TEST_BEGIN_64(VPMASKMOVDv256v256m256, 2)
TEST_INPUTS(TEST_INPUTS_MASK)
    push ARG1_64
    push ARG1_64
    push ARG1_64
    push ARG1_64
    vmovdqu ymm1, [rsp]
    push ARG2_64
    push ARG2_64
    push ARG2_64
    push ARG2_64
    vpmaskmovd ymm0, ymm1, [rsp] 
TEST_END_64

TEST_BEGIN_64(VPMASKMOVDm256v256v256, 2)
TEST_INPUTS(TEST_INPUTS_MASK)
    push ARG1_64
    push ARG1_64
    push ARG1_64
    push ARG1_64
    vmovdqu ymm2, [rsp]
    lea rcx, [rsp - 32]
    vpmaskmovd [rcx], ymm2, ymm0
TEST_END_64

TEST_BEGIN_64(VPMASKMOVQr128v128m128, 2)
TEST_INPUTS(TEST_INPUTS_MASK)
    push ARG1_64
    push ARG1_64
    vmovdqu xmm1, [rsp]
    push ARG2_64
    push ARG2_64
    vpmaskmovq xmm0, xmm1, [rsp] 
TEST_END_64

TEST_BEGIN_64(VPMASKMOVQm128v128v128, 2)
TEST_INPUTS(TEST_INPUTS_MASK)
    push ARG1_64
    push ARG1_64
    vmovdqu xmm2, [rsp]
    lea rcx, [rsp - 32]
    vpmaskmovq [rcx], xmm2, xmm0
TEST_END_64

TEST_BEGIN_64(VPMASKMOVQv256v256m256, 2)
TEST_INPUTS(TEST_INPUTS_MASK)
    push ARG1_64
    push ARG1_64
    push ARG1_64
    push ARG1_64
    vmovdqu ymm1, [rsp]
    push ARG2_64
    push ARG2_64
    push ARG2_64
    push ARG2_64
    vpmaskmovq ymm0, ymm1, [rsp] 
TEST_END_64

TEST_BEGIN_64(VPMASKMOVQm256v256v256, 2)
TEST_INPUTS(TEST_INPUTS_MASK)
    push ARG1_64
    push ARG1_64
    push ARG1_64
    push ARG1_64
    vmovdqu ymm2, [rsp]
    lea rcx, [rsp - 32]
    vpmaskmovq[rcx], ymm2, ymm0
TEST_END_64

#endif  // HAS_FEATURE_AVX