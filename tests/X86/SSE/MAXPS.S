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

#define MAXPS_INPUTS_32 \
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

TEST_BEGIN(MAXPSv128v128, 2)
TEST_INPUTS(MAXPS_INPUTS_32)
    movd xmm0, ARG1_32;      // load the low DWORD of v128 #1
    movd xmm1, ARG2_32;      // load the low DWORD of v128 #2
    maxps xmm0, xmm1;        // find the maximum of the two
TEST_END

TEST_BEGIN_64(MAXPSv128m128, 2)
TEST_INPUTS(MAXPS_INPUTS_32)
    movq xmm0, ARG1_64;      // load the low DWORD of v128  #1
    push ARG1_64;            // load the high DWORD of m128 #2:hi
    push ARG2_64;            // load the low DWORD of m128  #2:lo
    maxps xmm0, [rsp];       // return the maximum of the two
TEST_END_64
