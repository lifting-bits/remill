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

#define PSLL_INPUT_64           \
    0,                          \
    1,                          \
    0,                          \
    0x80,                       \
    0x7F,                       \
    0x80,                       \
    0x7FFF,                     \
    0x8000,                     \
    0x8000,                     \
    0x3FFFFFFF,                 \
    0x7FFFFFFF,                 \
    0x80000000,                 \
    0x7FFFFFFF,                 \
    0x80000000,                 \
    0x3ff0000000000000,         \
    0x3ff0000000000000,         \
    0x4000000000000000,         \
    0x7ff0000000000000,         \
    0x7ff0000000000000,         \
    0x8000000000000000,         \
    0x3ff0000000000000,         \
    0x7ff0000000000000,         \
    0x3ff0000000000000,         \
    0xfff0000000000000,         \
    0x7ff0000000000000,         \
    0xfff0000000000000,         \
    0x7ff8000000000000,         \
    0x7ff0000000000000,         \
    0x7ff8000000000000

#define PSLL_INPUTS_64          \
    0, 0,                       \
    1, 0,                       \
    0, 1,                       \
    1, 1,                       \
    0x80, 0x2,                  \
    0x7F, 0x2,                  \
    0x7FFF, 0x3,                \
    0x8000, 0x3,                \
    0x3FFFFFFF, 0x4,            \
    0x7FFFFFFF, 0x4,            \
    0x80000000, 0x4,            \
    0x7FFFFFFF, 0x5,            \
    0x80000000, 0x5,            \
    0x3ff0000000000000, 0x10,   \
    0x3ff0000000000000, 0xF,    \
    0x4000000000000000, 0xE,    \
    0x7ff0000000000000, 0xD,    \
    0x7ff0000000000000, 0xC,    \
    0x8000000000000000, 0xB,    \
    0x3ff0000000000000, 0xA,    \
    0x7ff0000000000000, 0x9,    \
    0x3ff0000000000000, 0x8,    \
    0xfff0000000000000, 0x7,    \
    0x7ff0000000000000, 0x6,    \
    0xfff0000000000000, 0xff,   \
    0x7ff8000000000000, 0x7ff8, \
    0x7ff0000000000000, 0x7ff8000000000000,\
    0x7ff8000000000000, 0x7ff0000000000000

TEST_BEGIN_64(PSLLWr64r64, 2)
TEST_INPUTS(PSLL_INPUTS_64)
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    psllw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PSLLWr64m64, 2)
TEST_INPUTS(PSLL_INPUTS_64)
    push ARG2_64
    movq mm0, ARG1_64
    psllw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSLLWv128v128, 2)
TEST_INPUTS(PSLL_INPUTS_64)
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    psllw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PSLLWv128m128, 2)
TEST_INPUTS(PSLL_INPUTS_64)
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    psllw xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSLLWr64i8, 1)
TEST_INPUTS(PSLL_INPUT_64)
    movq mm0, ARG1_64
    psllw mm0, 0xA
TEST_END_64

TEST_BEGIN_64(PSLLWv128i8, 1)
TEST_INPUTS(PSLL_INPUT_64)
    movq xmm0, ARG1_64
    psllw xmm0, 0xA
TEST_END_64

TEST_BEGIN_64(PSLLDr64r64, 2)
TEST_INPUTS(PSLL_INPUTS_64)
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pslld mm0, mm1
TEST_END_64

TEST_BEGIN_64(PSLLDv128v128, 2)
TEST_INPUTS(PSLL_INPUTS_64)
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pslld xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PSLLDr64m64, 2)
TEST_INPUTS(PSLL_INPUTS_64)
    push ARG2_64
    movq mm0, ARG1_64
    pslld mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSLLDv128m128, 2)
TEST_INPUTS(PSLL_INPUTS_64)
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pslld xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSLLDr64i8, 1)
TEST_INPUTS(PSLL_INPUT_64)
    movq mm0, ARG1_64
    pslld mm0, 0xA
TEST_END_64

TEST_BEGIN_64(PSLLDv128i8, 1)
TEST_INPUTS(PSLL_INPUT_64)
    movq xmm0, ARG1_64
    pslld xmm0, 0xA
TEST_END_64

TEST_BEGIN_64(PSLLQr64r64, 2)
TEST_INPUTS(PSLL_INPUTS_64)
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    psllq mm0, mm1
TEST_END_64

TEST_BEGIN_64(PSLLQr64m64, 2)
TEST_INPUTS(PSLL_INPUTS_64)
    push ARG2_64
    movq mm0, ARG1_64
    psllq mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSLLQr64i8, 1)
TEST_INPUTS(PSLL_INPUT_64)
    movq mm0, ARG1_64
    psllq mm0, 0xA
TEST_END_64

TEST_BEGIN_64(PSLLQv128v128, 2)
TEST_INPUTS(PSLL_INPUTS_64)
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    psllq xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PSLLQv128m128, 2)
TEST_INPUTS(PSLL_INPUTS_64)
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    psllq xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSLLQv128i8, 1)
TEST_INPUTS(PSLL_INPUT_64)
    movq xmm0, ARG1_64
    psllq xmm0, 0xA
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VPSLLQv128v128i8, 1)
TEST_INPUTS(PSLL_INPUT_64)
    movq xmm0, ARG1_64;
    vpsllq xmm1, xmm0, 0xA; 
TEST_END_64

TEST_BEGIN_64(VPSLLQv128v128v128, 2)
TEST_INPUTS(PSLL_INPUTS_64)
    movq xmm0, ARG1_64;
    movq xmm1, ARG2_64;
    vpsllq xmm2, xmm0, xmm1;
TEST_END_64

TEST_BEGIN_64(VPSLLQv128v128m128, 2)
TEST_INPUTS(PSLL_INPUTS_64)
    push 0;
    push ARG2_64;
    movq xmm0, ARG1_64;
    vpsllq xmm1, xmm0, xmmword ptr [rsp];
TEST_END_64

TEST_BEGIN_64(VPSLLQv256v256i8, 1)
TEST_INPUTS(0)
    vpsllq ymm0, ymm1, 0xA;
TEST_END_64

TEST_BEGIN_64(VPSLLQv256v256v128, 2)
TEST_INPUTS(0)
    vpsllq ymm0, ymm1, xmm0;
TEST_END_64

TEST_BEGIN_64(VPSLLQv256v256m128, 2)
TEST_INPUTS(PSLL_INPUT_64)
    push 0;
    push ARG1_64;
    vpsllq ymm0, ymm1, xmmword ptr [rsp];
TEST_END_64

#endif