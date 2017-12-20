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

#define SQRT_INPUTS_32 \
    0x41100000,   /* 9.0, a "perfect square," of which sqrt() is an integer */\
    0x00000000,   /* sqrt(0) should be 0 */\
    0x412E3D71,   /* 10.89, should return 3.33 */\
    0x411CCCCD,   /* 9.8, whose square root result needs to be rounded */\
    0x7fbfffff,   /* should return the SNaN converted to a QNaN */\
    0xffbfffff,   /* should return the -SNaN converted to a -QNaN */\
    0x7f800000,   /* inf */\
    0xBF800000,   /* -1.0, should return a constant (the QNaN floating-point indefinite) */\
    0xff800000,   /* -inf */\
    0x80000000    /* -0.0 */

TEST_BEGIN(SQRTSSv128v128, 1)
TEST_INPUTS(SQRT_INPUTS_32)
    movd xmm1, ARG1_32;      // load the low single-precision floating point value of v128
    sqrtss xmm0, xmm1;       // find the sqrt of the low SP FP value of xmm1, store in xmm0
TEST_END

TEST_BEGIN_64(SQRTSSv128m32, 1)
TEST_INPUTS(SQRT_INPUTS_32)
    push ARG1_64;           // load the low single-precision floating point value of m128
    sqrtss xmm0, dword ptr [rsp];     // sqrt of the low SP FP value of [rsp], store in xmm0
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VSQRTSSv128v128m32, 1)
TEST_INPUTS(SQRT_INPUTS_32)
    push ARG1_64;                  // load the single-prec. floating point value of m128[31:0]
    vsqrtss xmm2, xmm1, dword ptr [rsp];     // sqrt of [rsp] into xmm2, also xmm1[127:31]->xmm2
TEST_END_64

TEST_BEGIN_64(VSQRTSSv128v128v128, 1)
TEST_INPUTS(SQRT_INPUTS_32)
    push ARG1_64;               // the single-prec. float value in [31:0] of v128 #3 
    movq xmm0, qword ptr [rsp]; // load the single-prec. floating point value from v128 #3
    vsqrtss xmm2, xmm1, xmm0;   // return the sqrt of xmm0[31:0] into xmm2, also xmm1[127:31]->xmm2
TEST_END_64

#endif  // HAS_FEATURE_AVX
