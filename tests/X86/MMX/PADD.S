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

TEST_BEGIN_64(PADDBr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    paddb mm0, mm1
TEST_END_64

TEST_BEGIN_64(PADDBr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    paddb mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PADDBv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    paddb xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PADDBv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    paddb xmm0, xmmword ptr [rsp]
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VPADDBv128v128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64;
    movq xmm1, ARG2_64;
    vpaddb xmm2, xmm1, xmm0;
TEST_END_64

TEST_BEGIN_64(VPADDBv128v128m128, 2)
TEST_INPUTS_MMX_2()
    push 0;
    push ARG2_64;
    movq xmm0, ARG1_64;
    vpaddb xmm1, xmm0, xmmword ptr [rsp];
TEST_END_64

TEST_BEGIN_64(VPADDBv256v256m256, 2)
TEST_INPUTS(0)
    vmovdqu [rsp - 32], ymm0;
    vpaddb ymm0, ymm1, ymmword ptr [rsp - 32];
TEST_END_64

TEST_BEGIN_64(VPADDBv256v256v256, 2)
TEST_INPUTS(0)
    vpaddb ymm0, ymm1, ymm4;
TEST_END_64

#endif  // HAS_FEATURE_AVX


TEST_BEGIN_64(PADDWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    paddw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PADDWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    paddw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PADDWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    paddw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PADDWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    paddw xmm0, xmmword ptr [rsp]
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VPADDWv128v128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64;
    movq xmm1, ARG2_64;
    vpaddw xmm2, xmm1, xmm0;
TEST_END_64

TEST_BEGIN_64(VPADDWv128v128m128, 2)
TEST_INPUTS_MMX_2()
    push 0;
    push ARG2_64;
    movq xmm0, ARG1_64;
    vpaddw xmm1, xmm0, xmmword ptr [rsp];
TEST_END_64

TEST_BEGIN_64(VPADDWv256v256m256, 2)
TEST_INPUTS(0)
    vmovdqu [rsp - 32], ymm0;
    vpaddw ymm0, ymm1, ymmword ptr [rsp - 32];
TEST_END_64

TEST_BEGIN_64(VPADDWv256v256v256, 2)
TEST_INPUTS(0)
    vpaddw ymm0, ymm1, ymm4;
TEST_END_64

#endif  // HAS_FEATURE_AVX

TEST_BEGIN_64(PADDDr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    paddd mm0, mm1
TEST_END_64

TEST_BEGIN_64(PADDDr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    paddd mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PADDDv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    paddd xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PADDDv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    paddd xmm0, xmmword ptr [rsp]
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VPADDDv128v128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64;
    movq xmm1, ARG2_64;
    vpaddd xmm2, xmm1, xmm0;
TEST_END_64

TEST_BEGIN_64(VPADDDv128v128m128, 2)
TEST_INPUTS_MMX_2()
    push 0;
    push ARG2_64;
    movq xmm0, ARG1_64;
    vpaddd xmm1, xmm0, xmmword ptr [rsp];
TEST_END_64

TEST_BEGIN_64(VPADDDv256v256m256, 2)
TEST_INPUTS(0)
    vmovdqu [rsp - 32], ymm0;
    vpaddd ymm0, ymm1, ymmword ptr [rsp - 32];
TEST_END_64

TEST_BEGIN_64(VPADDDv256v256v256, 2)
TEST_INPUTS(0)
    vpaddd ymm0, ymm1, ymm4;
TEST_END_64

#endif  // HAS_FEATURE_AVX

TEST_BEGIN_64(PADDQr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    paddq mm0, mm1
TEST_END_64

TEST_BEGIN_64(PADDQr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    paddq mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PADDQv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    paddq xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PADDQv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    paddq xmm0, xmmword ptr [rsp]
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VPADDQv128v128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64;
    movq xmm1, ARG2_64;
    vpaddq xmm2, xmm1, xmm0;
TEST_END_64

TEST_BEGIN_64(VPADDQv128v128m128, 2)
TEST_INPUTS_MMX_2()
    push 0;
    push ARG2_64;
    movq xmm0, ARG1_64;
    vpaddq xmm1, xmm0, xmmword ptr [rsp];
TEST_END_64

TEST_BEGIN_64(VPADDQv256v256m256, 2)
TEST_INPUTS(0)
    vmovdqu [rsp - 32], ymm0;
    vpaddq ymm0, ymm1, ymmword ptr [rsp - 32];
TEST_END_64

TEST_BEGIN_64(VPADDQv256v256v256, 2)
TEST_INPUTS(0)
    vpaddq ymm0, ymm1, ymm4;
TEST_END_64

#endif  // HAS_FEATURE_AVX

TEST_BEGIN_64(PADDSBr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    paddsb mm0, mm1
TEST_END_64

TEST_BEGIN_64(PADDSBr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    paddsb mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PADDSBv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    paddsb xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PADDSBv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    paddsb xmm0, xmmword ptr [rsp]
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VPADDSBv128v128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64;
    movq xmm1, ARG2_64;
    vpaddsb xmm2, xmm1, xmm0;
TEST_END_64

TEST_BEGIN_64(VPADDSBv128v128m128, 2)
TEST_INPUTS_MMX_2()
    push 0;
    push ARG2_64;
    movq xmm0, ARG1_64;
    vpaddsb xmm1, xmm0, xmmword ptr [rsp];
TEST_END_64

TEST_BEGIN_64(VPADDSBv256v256m256, 2)
TEST_INPUTS(0)
    vmovdqu [rsp - 32], ymm0;
    vpaddsb ymm0, ymm1, ymmword ptr [rsp - 32];
TEST_END_64

TEST_BEGIN_64(VPADDSBv256v256v256, 2)
TEST_INPUTS(0)
    vpaddsb ymm0, ymm1, ymm4;
TEST_END_64

#endif  // HAS_FEATURE_AVX

TEST_BEGIN_64(PADDSWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    paddsw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PADDSWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    paddsw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PADDSWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    paddsw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PADDSWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    paddsw xmm0, xmmword ptr [rsp]
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VPADDSWv128v128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64;
    movq xmm1, ARG2_64;
    vpaddsw xmm2, xmm1, xmm0;
TEST_END_64

TEST_BEGIN_64(VPADDSWv128v128m128, 2)
TEST_INPUTS_MMX_2()
    push 0;
    push ARG2_64;
    movq xmm0, ARG1_64;
    vpaddsw xmm1, xmm0, xmmword ptr [rsp];
TEST_END_64

TEST_BEGIN_64(VPADDSWv256v256m256, 2)
TEST_INPUTS(0)
    vmovdqu [rsp - 32], ymm0;
    vpaddsw ymm0, ymm1, ymmword ptr [rsp - 32];
TEST_END_64

TEST_BEGIN_64(VPADDSWv256v256v256, 2)
TEST_INPUTS(0)
    vpaddsw ymm0, ymm1, ymm4;
TEST_END_64

#endif  // HAS_FEATURE_AVX

TEST_BEGIN_64(PHADDWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    phaddw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PHADDWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    phaddw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PHADDWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    phaddw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PHADDWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    phaddw xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PHADDDr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    phaddd mm0, mm1
TEST_END_64

TEST_BEGIN_64(PHADDDr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    phaddd mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PHADDDv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    phaddd xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PHADDDv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    phaddd xmm0, xmmword ptr [rsp]
TEST_END_64

#if HAS_FEATURE_AVX  

TEST_BEGIN_64(VPHADDWv128v128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm1, ARG1_64
    movq xmm2, ARG2_64
    vphaddw xmm0, xmm1, xmm2
TEST_END_64

TEST_BEGIN_64(VPHADDWv128v128m128, 2)
TEST_INPUTS_MMX_2()
    movq xmm1, ARG1_64   
    push 0                           // load high DWORD of v128
    push ARG2_64;                    // load low DWORD of v128
    vphaddw xmm0, xmm1, [rsp];
TEST_END_64

TEST_BEGIN_64(VPHADDWv256v256v256, 2)
TEST_INPUTS(0)
    vphaddw ymm0, ymm1, ymm2;
TEST_END_64

TEST_BEGIN_64(VPHADDWv256v256m256, 2)
TEST_INPUTS(0)
    vmovdqu [rsp - 32], ymm0;
    vphaddw ymm0, ymm1, ymmword ptr [rsp - 32];
TEST_END_64

TEST_BEGIN_64(VPHADDDv128v128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm1, ARG1_64
    movq xmm2, ARG2_64
    vphaddd xmm0, xmm1, xmm2
TEST_END_64

TEST_BEGIN_64(VPHADDDv128v128m128, 2)
TEST_INPUTS_MMX_2()
    movq xmm1, ARG1_64;
    push 0
    push ARG2_64;     
    vphaddd xmm0, xmm1, [rsp];
TEST_END_64

TEST_BEGIN_64(VPHADDDv256v256v256, 2)
TEST_INPUTS(0)
    vphaddd ymm0, ymm1, ymm2;
TEST_END_64

TEST_BEGIN_64(VPHADDDv256v256m256, 2)
TEST_INPUTS(0)
    vmovdqu [rsp - 32], ymm0;
    vphaddd ymm0, ymm1, ymmword ptr [rsp - 32];
TEST_END_64

TEST_BEGIN_64(VPHADDSWv128v128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm1, ARG1_64
    movq xmm2, ARG2_64
    vphaddsw xmm0, xmm1, xmm2
TEST_END_64

TEST_BEGIN_64(VPHADDSWv128v128m128, 2)
TEST_INPUTS_MMX_2()
    push 0;
    push ARG2_64;
    movq xmm0, ARG1_64;
    vphaddsw xmm0, xmm1, xmmword ptr [rsp];
TEST_END_64

TEST_BEGIN_64(VPHADDSWv256v256v256, 2)
TEST_INPUTS(0)
    vphaddsw ymm0, ymm1, ymm2;
TEST_END_64

TEST_BEGIN_64(VPHADDSWv256v256m256, 2)
TEST_INPUTS(0)
    vmovdqu [rsp - 32], ymm0;
    vphaddsw ymm0, ymm1, ymmword ptr [rsp - 32];
TEST_END_64

#endif  // HAS_FEATURE_AVX

TEST_BEGIN_64(PHADDSWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    phaddsw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PHADDSWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    phaddsw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PHADDSWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    phaddsw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PHADDSWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    phaddsw xmm0, xmmword ptr [rsp]
TEST_END_64
