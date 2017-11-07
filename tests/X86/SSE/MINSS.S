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

#define MINSS_INPUTS_32 \
    0.0, 1.2,               /* ARG1 < ARG2 */\
    3.4, 2.3,               /* ARG1 > ARG2 */\
    5.5, 5.5,               /* ARG1 == ARG2 */\
    0x7fc00000, 0x7fc00000, /* QNaN, QNaN */\
    0xffc00000, 0xffc00000, /* -QNaN, -QNaN */\
    0x7fc00000, 0xffc00000, /* QNaN, -QNaN */\
    0xffc00000, 0x7fc00000, /* -QNaN, QNaN */\
    0x7fbfffff, 0x7fbfffff, /* SNaN, SNaN */\
    0xffbfffff, 0xffbfffff, /* -SNaN, -SNaN */\
    0x7fbfffff, 0xffbfffff, /* SNaN, -SNaN */\
    0xffbfffff, 0x7fbfffff, /* -SNaN, SNaN */\
    0x7f800000, 0x7f800000, /* inf, inf */\
    0x7f800000, 0xff800000, /* inf, -inf */\
    0xff800000, 0x7f800000, /* -inf, inf */\
    0x00000000, 0x00000000, /* 0.000000, 0.000000 */\
    0x80000000, 0x80000000, /* -0.000000, -0.000000 */\
    0x00000000, 0x80000000, /* 0.000000, -0.000000 */\
    0x80000000, 0x00000000, /* -0.000000, 0.000000 */\
    0x3f800000, 0x7fc00000, /* 1.000000, QNaN */\
    0x7fc00000, 0x3f800000, /* QNaN, 1.000000 */\
    0x3f800000, 0x7fbfffff, /* 1.000000, SNaN */\
    0x7fbfffff, 0x3f800000, /* SNaN, 1.000000 */\
    0x7f800000, 0x7fc00000, /* inf, QNaN */\
    0x7fc00000, 0x7f800000, /* QNaN, inf */\
    0x7f800000, 0x7fbfffff, /* inf, SNaN */\
    0x7fbfffff, 0x7f800000, /* SNaN, inf */\
    0x3f800000, 0x7f800000, /* 1.000000, inf */\
    0x3f800000, 0xff800000, /* 1.000000, -inf */\
    0x7f800000, 0x3f800000, /* inf, 1.000000 */\
    0xff800000, 0x3f800000, /* -inf, 1.000000 */\
    0x3f800000, 0xbf800000, /* 1.000000, -1.000000 */\
    0xbf800000, 0x3f800000  /* -1.000000, 1.000000 */

TEST_BEGIN(MINSSv128v128, 2)
TEST_INPUTS(MINSS_INPUTS_32)
    movd xmm0, ARG1_32;      // load the low DWORD of v128 #1
    movd xmm1, ARG2_32;      // load the low DWORD of v128 #2
    minss xmm0, xmm1;        // find the minimum of the low DWORD of the two vectors
TEST_END

TEST_BEGIN_64(MINSSv128m32, 2)
TEST_INPUTS(MINSS_INPUTS_32)
    movq xmm0, ARG1_64;     // load the low DWORD of v128
    push ARG2_64;           // load this low DWORD as the m32
    minss xmm0, dword ptr [rsp];      // find the minimum of the two
TEST_END_64


#if HAS_FEATURE_AVX

TEST_BEGIN_64(VMINSSv128v128m32, 2)
TEST_INPUTS(MINSS_INPUTS_32)
    push ARG1_64;
    push ARG2_64;                 // load the low DWORD of this as m32
    movq xmm1, qword ptr [rsp+8]; // load the low DWORD of the v128
    vminss xmm2, xmm1, dword ptr [rsp];     // return the minimum of low DWORDs into v128 xmm2
TEST_END_64

TEST_BEGIN_64(VMINSSv128v128v128, 2)
TEST_INPUTS(MINSS_INPUTS_32)
    push ARG1_64;
    push ARG2_64;
    movq xmm0, qword ptr [rsp+8]; // load the low DWORD of v128 #2
    movq xmm1, qword ptr [rsp];   // load the low DWORD of v128 #1
    vminss xmm2, xmm1, xmm0;      // return the minimum of the low DWORDs into v128 xmm2
TEST_END_64

#endif  // HAS_FEATURE_AVX
