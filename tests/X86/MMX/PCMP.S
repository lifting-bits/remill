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

TEST_BEGIN_64(PCMPEQBr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pcmpeqb mm0, mm1
TEST_END_64

TEST_BEGIN_64(PCMPEQBr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pcmpeqb mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PCMPEQBv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pcmpeqb xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PCMPEQBv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    pcmpeqb xmm0, xmmword ptr [rsp]
    movq xmm1, ARG1_64
    pcmpeqb xmm1, xmmword ptr [rsp]
TEST_END_64

#if HAS_FEATURE_AVX
TEST_BEGIN_64(VPCMPEQBv128v128v128, 1)
TEST_INPUTS(0)
    vpcmpeqb xmm2, xmm1, xmm0
TEST_END_64

TEST_BEGIN_64(VPCMPEQBv256v256v256, 1)
TEST_INPUTS(0)
    vpcmpeqb xmm2, xmm1, xmm0
TEST_END_64
#endif  // HAS_FEATURE_AVX

TEST_BEGIN_64(PCMPEQWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pcmpeqw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PCMPEQWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pcmpeqw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PCMPEQWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pcmpeqw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PCMPEQWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pcmpeqw xmm0, xmmword ptr [rsp]
TEST_END_64

#if HAS_FEATURE_AVX
TEST_BEGIN_64(VPCMPEQWv128v128v128, 1)
TEST_INPUTS(0)
    vpcmpeqw xmm2, xmm1, xmm0
TEST_END_64

TEST_BEGIN_64(VPCMPEQWv256v256v256, 1)
TEST_INPUTS(0)
    vpcmpeqw xmm2, xmm1, xmm0
TEST_END_64
#endif  // HAS_FEATURE_AVX

TEST_BEGIN_64(PCMPEQDr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pcmpeqd mm0, mm1
TEST_END_64

TEST_BEGIN_64(PCMPEQDr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pcmpeqd mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PCMPEQDv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pcmpeqd xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PCMPEQDv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pcmpeqd xmm0, xmmword ptr [rsp]
TEST_END_64

#if HAS_FEATURE_AVX
TEST_BEGIN_64(VPCMPEQDv128v128v128, 1)
TEST_INPUTS(0)
    vpcmpeqd xmm2, xmm1, xmm0
TEST_END_64

TEST_BEGIN_64(VPCMPEQDv256v256v256, 1)
TEST_INPUTS(0)
    vpcmpeqd xmm2, xmm1, xmm0
TEST_END_64
#endif  // HAS_FEATURE_AVX

TEST_BEGIN_64(PCMPEQQv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pcmpeqq xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PCMPEQQv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pcmpeqq xmm0, xmmword ptr [rsp]
TEST_END_64

#if HAS_FEATURE_AVX
TEST_BEGIN_64(VPCMPEQQv128v128v128, 1)
TEST_INPUTS(0)
    vpcmpeqq xmm2, xmm1, xmm0
TEST_END_64

TEST_BEGIN_64(VPCMPEQQv256v256v256, 1)
TEST_INPUTS(0)
    vpcmpeqq xmm2, xmm1, xmm0
TEST_END_64
#endif  // HAS_FEATURE_AVX

TEST_BEGIN_64(PCMPGTBr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pcmpgtb mm0, mm1
TEST_END_64

TEST_BEGIN_64(PCMPGTBr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pcmpgtb mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PCMPGTBv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pcmpgtb xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PCMPGTBv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pcmpgtb xmm0, xmmword ptr [rsp]
TEST_END_64

#if HAS_FEATURE_AVX
TEST_BEGIN_64(VPCMPGTBv128v128v128, 1)
TEST_INPUTS(0)
    vpcmpgtb xmm2, xmm1, xmm0
TEST_END_64

TEST_BEGIN_64(VPCMPGTBv256v256v256, 1)
TEST_INPUTS(0)
    vpcmpgtb xmm2, xmm1, xmm0
TEST_END_64
#endif  // HAS_FEATURE_AVX

TEST_BEGIN_64(PCMPGTWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pcmpgtw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PCMPGTWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pcmpgtw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PCMPGTWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pcmpgtw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PCMPGTWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pcmpgtw xmm0, xmmword ptr [rsp]
TEST_END_64

#if HAS_FEATURE_AVX
TEST_BEGIN_64(VPCMPGTWv128v128v128, 1)
TEST_INPUTS(0)
    vpcmpgtw xmm2, xmm1, xmm0
TEST_END_64

TEST_BEGIN_64(VPCMPGTWv256v256v256, 1)
TEST_INPUTS(0)
    vpcmpgtw xmm2, xmm1, xmm0
TEST_END_64
#endif  // HAS_FEATURE_AVX

TEST_BEGIN_64(PCMPGTDr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pcmpgtd mm0, mm1
TEST_END_64

TEST_BEGIN_64(PCMPGTDr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pcmpgtd mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PCMPGTDv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pcmpgtd xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PCMPGTDv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pcmpgtd xmm0, xmmword ptr [rsp]
TEST_END_64

#if HAS_FEATURE_AVX
TEST_BEGIN_64(VPCMPGTDv128v128v128, 1)
TEST_INPUTS(0)
    vpcmpgtd xmm2, xmm1, xmm0
TEST_END_64

TEST_BEGIN_64(VPCMPGTDv256v256v256, 1)
TEST_INPUTS(0)
    vpcmpgtd xmm2, xmm1, xmm0
TEST_END_64
#endif  // HAS_FEATURE_AVX

TEST_BEGIN_64(PCMPGTQv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pcmpgtq xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PCMPGTQv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pcmpgtq xmm0, xmmword ptr [rsp]
TEST_END_64

#if HAS_FEATURE_AVX
TEST_BEGIN_64(VPCMPGTQv128v128v128, 1)
TEST_INPUTS(0)
    vpcmpgtq xmm2, xmm1, xmm0
TEST_END_64

TEST_BEGIN_64(VPCMPGTQv256v256v256, 1)
TEST_INPUTS(0)
    vpcmpgtq xmm2, xmm1, xmm0
TEST_END_64
#endif  // HAS_FEATURE_AVX
