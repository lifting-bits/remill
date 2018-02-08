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

TEST_BEGIN_64(SQRTSDv128v128, 1)
TEST_INPUTS(SQRT_INPUTS_64)
    movq xmm1, ARG1_64;      // load the low double-precision floating point value of v128
    sqrtsd xmm0, xmm1;       // find the sqrt of the low DP FP value of xmm1, store in xmm0
TEST_END_64

TEST_BEGIN_64(SQRTSDv128m64, 1)
TEST_INPUTS(SQRT_INPUTS_64)
    push ARG1_64;           // load the low double-precision floating point value of m128
    sqrtsd xmm0, qword ptr [rsp];  // sqrt of the low DP FP value of [rsp], store in xmm0
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VSQRTSDv128v128m64, 1)
TEST_INPUTS(SQRT_INPUTS_64)
    push ARG1_64;           // load the double-precision floating point value of m128[63:0]
    vsqrtsd xmm2, xmm1, qword ptr [rsp];  // sqrt of [rsp] into xmm2, also xmm1[127:64]->xmm2
TEST_END_64

TEST_BEGIN_64(VSQRTSDv128v128v128, 1)
TEST_INPUTS(SQRT_INPUTS_64)
    push ARG1_64;               // the double-prec. float value in [63:0] of v128 #3
    movq xmm0, qword ptr [rsp]; // load the double-prec. floating point value from v128 #3
    vsqrtsd xmm2, xmm1, xmm0;   // return the sqrt of xmm0[63:0] into xmm2, also xmm1[127:64]->xmm2
TEST_END_64

#endif  // HAS_FEATURE_AVX