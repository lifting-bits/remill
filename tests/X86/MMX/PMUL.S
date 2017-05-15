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

TEST_BEGIN_64(PMADDUBSWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pmaddubsw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PMADDUBSWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pmaddubsw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PMADDUBSWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pmaddubsw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PMADDUBSWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pmaddubsw xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PMADDWDr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pmaddwd mm0, mm1
TEST_END_64

TEST_BEGIN_64(PMADDWDr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pmaddwd mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PMADDWDv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pmaddwd xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PMADDWDv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pmaddwd xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PMULUDQr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pmuludq mm0, mm1
TEST_END_64

TEST_BEGIN_64(PMULUDQr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pmuludq mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PMULUDQv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pmuludq xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PMULUDQv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pmuludq xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PMULLWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pmullw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PMULLWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pmullw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PMULLWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pmullw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PMULLWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pmullw xmm0, xmmword ptr [rsp]
TEST_END_64
TEST_BEGIN_64(PMULHWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pmulhw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PMULHWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pmulhw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PMULHWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pmulhw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PMULHWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pmulhw xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PMULHUWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pmulhuw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PMULHUWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pmulhuw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PMULHUWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pmulhuw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PMULHUWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pmulhuw xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PMULHRSWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pmulhrsw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PMULHRSWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pmulhrsw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PMULHRSWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pmulhrsw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PMULHRSWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pmulhrsw xmm0, xmmword ptr [rsp]
TEST_END_64

