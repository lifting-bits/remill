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

#define MINSD_INPUTS_64 \
    0.0, 1.2,               /* ARG1 < ARG2 */\
    3.4, 2.3,               /* ARG1 > ARG2 */\
    5.5, 5.5,               /* ARG1 == ARG2 */\
    0x7ff8000000000000, 0x7ff8000000000000, /* QNaN, QNaN */\
    0xfff8000000000001, 0xfff8000000000001, /* -QNaN, -QNaN */\
    0x7ff8000000000000, 0xfff8000000000001, /* QNaN, -QNaN */\
    0xfff8000000000001, 0x7ff8000000000000, /* -QNaN, QNaN */\
    0x7ff0000000000001, 0x7ff0000000000001, /* SNaN, SNaN */\
    0xfff0000000000001, 0xfff0000000000001, /* -SNaN, -SNaN */\
    0x7ff0000000000001, 0xfff0000000000001, /* SNaN, -SNaN */\
    0xfff0000000000001, 0x7ff0000000000001, /* -SNaN, SNaN */\
    0x7ff0000000000000, 0x7ff0000000000000, /* inf, inf */\
    0x7ff0000000000000, 0xfff0000000000000, /* inf, -inf */\
    0xfff0000000000000, 0x7ff0000000000000, /* -inf, inf */\
    0x0000000000000000, 0x0000000000000000, /* 0.000000, 0.000000 */\
    0x8000000000000000, 0x8000000000000000, /* -0.000000, -0.000000 */\
    0x0000000000000000, 0x8000000000000000, /* 0.000000, -0.000000 */\
    0x8000000000000000, 0x0000000000000000, /* -0.000000, 0.000000 */\
    0x3ff0000000000000, 0x7ff8000000000000, /* 1.000000, QNaN */\
    0x7ff8000000000000, 0x3ff0000000000000, /* QNaN, 1.000000 */\
    0x3ff0000000000000, 0x7ff0000000000001, /* 1.000000, SNaN */\
    0x7ff0000000000001, 0x3ff0000000000000, /* SNaN, 1.000000 */\
    0x7ff0000000000000, 0x7ff8000000000000, /* inf, QNaN */\
    0x7ff8000000000000, 0x7ff0000000000000, /* QNaN, inf */\
    0x7ff0000000000000, 0x7ff0000000000001, /* inf, SNaN */\
    0x7ff0000000000001, 0x7ff0000000000000, /* SNaN, inf */\
    0x3ff0000000000000, 0x7ff0000000000000, /* 1.000000, inf */\
    0x3ff0000000000000, 0xfff0000000000000, /* 1.000000, -inf */\
    0x7ff0000000000000, 0x3ff0000000000000, /* inf, 1.000000 */\
    0xfff0000000000000, 0x3ff0000000000000, /* -inf, 1.000000 */\
    0x3ff0000000000000, 0xbff0000000000000, /* 1.000000, -1.000000 */\
    0xbff0000000000000, 0x3ff0000000000000  /* -1.000000, 1.000000 */

TEST_BEGIN_64(MINSDv128v128, 2)
TEST_INPUTS(MINSD_INPUTS_64)
    movq xmm0, ARG1_64;      // load the low QWORD of v128 #1
    movq xmm1, ARG2_64;      // load the low QWORD of v128 #2
    minsd xmm0, xmm1;        // find the minimum of the low QWORD of the two vectors
TEST_END_64

TEST_BEGIN_64(MINSDv128m64, 2)
TEST_INPUTS(MINSD_INPUTS_64)
    movq xmm0, ARG1_64;     // load the low QWORD of v128
    push ARG2_64;           // load this QWORD as the m64
    minsd xmm0, qword ptr [rsp];      // find the minimum of the two
TEST_END_64


#if HAS_FEATURE_AVX

TEST_BEGIN_64(VMINSDv128v128m64, 2)
TEST_INPUTS(MINSD_INPUTS_64)
    push ARG1_64;
    push ARG2_64;                 // load this QWORD as the m64
    movq xmm1, qword ptr [rsp+8]; // load the low QWORD of v128 #1
    vminsd xmm2, xmm1, qword ptr [rsp];     // return the minimum of the two into xmm2
TEST_END_64

TEST_BEGIN_64(VMINSDv128v128v128, 2)
TEST_INPUTS(MINSD_INPUTS_64)
    push ARG1_64;
    push ARG2_64;
    movq xmm0, qword ptr [rsp+8]; // load the low QWORD of v128 #1
    movq xmm1, qword ptr [rsp];   // load the low QWORD of v128 #2
    vminsd xmm2, xmm1, xmm0;      // return the minimum of the two into xmm2
TEST_END_64

#endif  // HAS_FEATURE_AVX
