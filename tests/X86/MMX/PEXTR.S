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

TEST_BEGIN_64(PEXTRB_0, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrb eax, xmm0, 0
TEST_END_64

TEST_BEGIN_64(PEXTRB_1, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrb eax, xmm0, 1
TEST_END_64

TEST_BEGIN_64(PEXTRB_7, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrb eax, xmm0, 7
TEST_END_64

TEST_BEGIN_64(PEXTRB_15, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrb eax, xmm0, 15
TEST_END_64

TEST_BEGIN_64(PEXTRB_16, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrb eax, xmm0, 16
TEST_END_64


TEST_BEGIN_64(PEXTRW_0, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrw eax, xmm0, 0
TEST_END_64

TEST_BEGIN_64(PEXTRW_1, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrw eax, xmm0, 1
TEST_END_64

TEST_BEGIN_64(PEXTRW_2, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrw eax, xmm0, 2
TEST_END_64

TEST_BEGIN_64(PEXTRW_3, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrw eax, xmm0, 3
TEST_END_64

TEST_BEGIN_64(PEXTRW_7, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrw eax, xmm0, 7
TEST_END_64

TEST_BEGIN_64(PEXTRW_8, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrw eax, xmm0, 8
TEST_END_64




TEST_BEGIN_64(PEXTRD_0, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrd eax, xmm0, 0
TEST_END_64

TEST_BEGIN_64(PEXTRD_1, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrd eax, xmm0, 1
TEST_END_64

TEST_BEGIN_64(PEXTRD_2, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrd eax, xmm0, 2
TEST_END_64

TEST_BEGIN_64(PEXTRD_3, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrd eax, xmm0, 3
TEST_END_64

TEST_BEGIN_64(PEXTRD_4, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrd eax, xmm0, 4
TEST_END_64





TEST_BEGIN_64(PEXTRQ_1, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrq rax, xmm0, 1
TEST_END_64

TEST_BEGIN_64(PEXTRQ_2, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrq rax, xmm0, 2
TEST_END_64

TEST_BEGIN_64(PEXTRQ_3, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrq rax, xmm0, 3
TEST_END_64
