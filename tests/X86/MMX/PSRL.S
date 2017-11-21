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

#define PSRL_INPUT_64           \
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

#define PSRL_INPUTS_64          \
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

TEST_BEGIN_64(PSRLWr64r64, 2)
TEST_INPUTS(PSRL_INPUTS_64)
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    psrlw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PSRLWv128v128, 2)
TEST_INPUTS(PSRL_INPUTS_64)
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    psrlw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PSRLWr64m64, 2)
TEST_INPUTS(PSRL_INPUTS_64)
    push ARG2_64
    movq mm0, ARG1_64
    psrlw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSRLWv128m128, 2)
TEST_INPUTS(PSRL_INPUTS_64)
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    psrlw xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSRLWr64i8, 1)
TEST_INPUTS(PSRL_INPUT_64)
    movq mm0, ARG1_64
    psrlw mm0, 0xA
TEST_END_64

TEST_BEGIN_64(PSRLWv128i8, 1)
TEST_INPUTS(PSRL_INPUT_64)
    movq xmm0, ARG1_64
    psrlw xmm0, 0xA
TEST_END_64

TEST_BEGIN_64(PSRLDr64r64, 2)
TEST_INPUTS(PSRL_INPUTS_64)
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    psrld mm0, mm1
TEST_END_64

TEST_BEGIN_64(PSRLDv128v128, 2)
TEST_INPUTS(PSRL_INPUTS_64)
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    psrld xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PSRLDr64m64, 2)
TEST_INPUTS(PSRL_INPUTS_64)
    push ARG2_64
    movq mm0, ARG1_64
    psrld mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSRLDv128m128, 2)
TEST_INPUTS(PSRL_INPUTS_64)
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    psrld xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSRLDr64i8, 1)
TEST_INPUTS(PSRL_INPUT_64)
    movq mm0, ARG1_64
    psrld mm0, 0xA
TEST_END_64

TEST_BEGIN_64(PSRLDv128i8, 1)
TEST_INPUTS(PSRL_INPUT_64)
    movq xmm0, ARG1_64
    psrld xmm0, 0xA
TEST_END_64

TEST_BEGIN_64(PSRLQr64r64, 2)
TEST_INPUTS(PSRL_INPUTS_64)
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    psrlq mm0, mm1
TEST_END_64

TEST_BEGIN_64(PSRLQv128v128, 2)
TEST_INPUTS(PSRL_INPUTS_64)
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    psrlq xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PSRLQr64m64, 2)
TEST_INPUTS(PSRL_INPUTS_64)
    push ARG2_64
    movq mm0, ARG1_64
    psrlq mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSRLQv128m128, 2)
TEST_INPUTS(PSRL_INPUTS_64)
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    psrlq xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSRLQr64i8, 1)
TEST_INPUTS(PSRL_INPUT_64)
    movq mm0, ARG1_64
    psrlq mm0, 0xA
TEST_END_64

TEST_BEGIN_64(PSRLQv128i8, 1)
TEST_INPUTS(PSRL_INPUT_64)
    movq xmm0, ARG1_64
    psrlq xmm0, 0xA
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VPSRLQv128v128m128, 2)
TEST_INPUTS(PSRL_INPUTS_64)
    push 0;
    push ARG2_64;
    movq xmm0, ARG1_64;
    vpsrlq xmm1, xmm0, xmmword ptr [rsp];
TEST_END_64

TEST_BEGIN_64(VPSRLQv128v128v128, 2)
TEST_INPUTS(PSRL_INPUTS_64)
    movq xmm0, ARG1_64;
    movq xmm1, ARG2_64;
    vpsrlq xmm2, xmm1, xmm0;
TEST_END_64

TEST_BEGIN_64(VPSRLQv128v128i8, 1)
TEST_INPUTS(PSRL_INPUT_64)
    movq xmm0, ARG1_64;
    vpsrlq xmm1, xmm0, 0xA;
TEST_END_64

TEST_BEGIN_64(VPSRLQv256v256i8, 1)
TEST_INPUTS(0)
    vpsrlq ymm0, ymm1, 0xA;
TEST_END_64

TEST_BEGIN_64(VPSRLQv256v256v128, 2)
TEST_INPUTS(0)
    vpsrlq ymm0, ymm1, xmm0;
TEST_END_64

TEST_BEGIN_64(VPSRLQv256v256m128, 2)
TEST_INPUTS(PSRL_INPUT_64)
    push 0;
    push ARG1_64;
    vpsrlq ymm0, ymm1, xmmword ptr [rsp];
TEST_END_64

#endif  // HAS_FEATURE_AVX

TEST_BEGIN_64(PSRAWr64r64, 2)
TEST_INPUTS(PSRL_INPUTS_64)
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    psraw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PSRAWv128v128, 2)
TEST_INPUTS(PSRL_INPUTS_64)
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    psraw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PSRAWr64m64, 2)
TEST_INPUTS(PSRL_INPUTS_64)
    push ARG2_64
    movq mm0, ARG1_64
    psraw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSRAWv128m128, 2)
TEST_INPUTS(PSRL_INPUTS_64)
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    psraw xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSRAWr64i8, 1)
TEST_INPUTS(PSRL_INPUT_64)
    movq mm0, ARG1_64
    psraw mm0, 0xA
TEST_END_64

TEST_BEGIN_64(PSRAWv128i8, 1)
TEST_INPUTS(PSRL_INPUT_64)
    movq xmm0, ARG1_64
    psraw xmm0, 0xA
TEST_END_64

TEST_BEGIN_64(PSRADr64r64, 2)
TEST_INPUTS(PSRL_INPUTS_64)
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    psrad mm0, mm1
TEST_END_64

TEST_BEGIN_64(PSRADv128v128, 2)
TEST_INPUTS(PSRL_INPUTS_64)
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    psrad xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PSRADr64m64, 2)
TEST_INPUTS(PSRL_INPUTS_64)
    push ARG2_64
    movq mm0, ARG1_64
    psrad mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSRADv128m128, 2)
TEST_INPUTS(PSRL_INPUTS_64)
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    psrad xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSRADr64i8, 1)
TEST_INPUTS(PSRL_INPUT_64)
    movq mm0, ARG1_64
    psrad mm0, 0xA
TEST_END_64

TEST_BEGIN_64(PSRADv128i8, 1)
TEST_INPUTS(PSRL_INPUT_64)
    movq xmm0, ARG1_64
    psrad xmm0, 0xA
TEST_END_64
