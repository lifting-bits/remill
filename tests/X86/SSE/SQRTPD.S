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


#define SQRT_INPUTS_64 \
    0x4022000000000000,   /* 9.0, a "perfect square," of which sqrt() is an integer */\
    0x0000000000000000,   /* 0.0, and sqrt(0) should be 0 */\
    0x4025C7AE147AE148,   /* 10.89, should return 3.33 */\
    0x402399999999999A,   /* 9.8, whose square root result needs to be rounded */\
    0x7FF0000000000001,   /* SNaN, should convert to a QNaN */\
    0xFFF0000000000001,   /* -SNaN, should convert to a -QNaN */\
    0x7FF0000000000000,   /* inf */\
    0xBFF0000000000000,   /* -1.0, should return a constant (the QNaN floating-point indefinite) */\
    0xFFF0000000000000,   /* -inf */\
    0x8000000000000000    /* -0.0 */

TEST_BEGIN_64(SQRTPDv128v128, 2)
TEST_INPUTS(SQRT_INPUTS_64)
    movq xmm1, ARG1_64;      // load the first double-precision floating point value into xmm1[63:0]
    movq xmm2, ARG2_64;      // load the second double-precision floating point value into xmm2[63:0]
    movlhpd xmm1, xmm2;      // pack both values: xmm1[127:64] = xmm2[63:0], xmm1[63:0] unchanged
    sqrtpd xmm0, xmm1;       // find the sqrt of both DP FP values of xmm1, store in xmm0
TEST_END_64

TEST_BEGIN_64(SQRTPDv128m128, 2)
TEST_INPUTS(SQRT_INPUTS_64)
    push ARG2_64;            // push the second double-precision floating point value (high QWORD)
    push ARG1_64;            // push the first double-precision floating point value (low QWORD)
    sqrtpd xmm0, xmmword ptr [rsp];  // sqrt of both DP FP values at [rsp], store in xmm0
TEST_END_64

