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

TEST_BEGIN_64(PACKSSWBr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    packsswb mm0, mm1
TEST_END_64

TEST_BEGIN_64(PACKSSWBr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    packsswb mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PACKSSWBv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    packsswb xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PACKSSWBv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    packsswb xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PACKSSDWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    packssdw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PACKSSDWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    packssdw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PACKSSDWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    packssdw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PACKSSDWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    packssdw xmm0, xmmword ptr [rsp]
TEST_END_64
