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

TEST_BEGIN_64(PAVGBr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pavgb mm0, mm1
TEST_END_64

TEST_BEGIN_64(PAVGBr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pavgb mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PAVGBv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pavgb xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PAVGBv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pavgb xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PAVGWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pavgw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PAVGWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pavgw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PAVGWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pavgw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PAVGWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pavgw xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PABSBr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pabsb mm0, mm1
TEST_END_64

TEST_BEGIN_64(PABSBr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pabsb mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PABSBv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pabsb xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PABSBv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pabsb xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PABSWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pabsw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PABSWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pabsw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PABSWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pabsw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PABSWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pabsw xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PAVGDr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pabsd mm0, mm1
TEST_END_64

TEST_BEGIN_64(PAVGDr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pabsd mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PAVGDv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pabsd xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PAVGDv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pabsd xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PMAXSWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pmaxsw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PMAXSWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pmaxsw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PMAXSWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pmaxsw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PMAXSWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pmaxsw xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PMAXUBr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pmaxub mm0, mm1
TEST_END_64

TEST_BEGIN_64(PMAXUBr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pmaxub mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PMAXUBv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pmaxub xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PMAXUBv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pmaxub xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PMINSWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pminsw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PMINSWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pminsw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PMINSWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pminsw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PMINSWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pminsw xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PMINUBr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pminub mm0, mm1
TEST_END_64

TEST_BEGIN_64(PMINUBr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pminub mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PMINUBv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pminub xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PMINUBv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pminub xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PALIGNR_64r64r64i8_0, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    palignr mm0, mm1, 0
TEST_END_64

TEST_BEGIN_64(PALIGNR_64r64r64i8_1, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    palignr mm0, mm1, 1
TEST_END_64

TEST_BEGIN_64(PALIGNR_64r64r64i8_2, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    palignr mm0, mm1, 2
TEST_END_64

TEST_BEGIN_64(PALIGNR_64r64r64i8_7, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    palignr mm0, mm1, 7
TEST_END_64

TEST_BEGIN_64(PALIGNR_64r64r64i8_8, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    palignr mm0, mm1, 8
TEST_END_64

TEST_BEGIN_64(PALIGNR_64r64m64i8_1, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    palignr mm0, qword ptr [rsp], 1
TEST_END_64

TEST_BEGIN_64(PALIGNR_128v128v128i8_0, 1)
TEST_INPUTS()
    palignr xmm4, xmm1, 1
TEST_END_64

TEST_BEGIN_64(PALIGNR_128v128v128i8_1, 1)
TEST_INPUTS()
    palignr xmm4, xmm1, 1
TEST_END_64

TEST_BEGIN_64(PALIGNR_128v128v128i8_4, 1)
TEST_INPUTS()
    palignr xmm4, xmm1, 4
TEST_END_64

TEST_BEGIN_64(PALIGNR_128v128v128i8_7, 1)
TEST_INPUTS()
    palignr xmm4, xmm1, 7
TEST_END_64

TEST_BEGIN_64(PALIGNR_128v128v128i8_8, 1)
TEST_INPUTS()
    palignr xmm4, xmm1, 8
TEST_END_64

TEST_BEGIN_64(PALIGNR_128v128v128i8_15, 1)
TEST_INPUTS()
    palignr xmm4, xmm1, 15
TEST_END_64

TEST_BEGIN_64(PALIGNR_128v128v128i8_16, 1)
TEST_INPUTS()
    palignr xmm4, xmm1, 16
TEST_END_64

TEST_BEGIN_64(PALIGNR_64r64m64i8, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    palignr mm0, qword ptr [rsp], 1
TEST_END_64

TEST_BEGIN_64(MASKMOVQr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    lea rdi, [rsp - 8]
    maskmovq mm0, mm1
TEST_END_64
