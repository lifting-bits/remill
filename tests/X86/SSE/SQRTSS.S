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

TEST_BEGIN(SQRTSSv128v128, 2)
TEST_INPUTS(
    0x00000000, 9.00000,        // a "perfect square," of which sqrt() is an integer
    0x12345678, 9.00000,        // doesn't matter what we initialize to dest, as long as we do
    0x00000000, 0.00000,        // sqrt(0) should be 0
    0x00000000, -1.00000,       // should return a constant (the QNaN floating-point indefinite)
    0x00000000, 10.89,         // should be 3.33
//    0x00000000, 9.8,        // a test for sqrt where the result would need to be truncated (fail)
    0x00000000, 0x7fbfffff,      // should return the SNaN converted to a QNaN
    0x00000000, 0xffbfffff,      // should return the -SNaN converted to a -QNaN
    0x00000000, 0x7f800000)      // inf
//    0x00000000, 0xff800000)      // -inf (fail)
    movd xmm0, ARG1_32;
    movd xmm1, ARG2_32;      // load the low single-precision floating point value of v128
    sqrtss xmm0, xmm1;       // find the sqrt of the low SP FP value of xmm1, store in xmm0
TEST_END

TEST_BEGIN_64(SQRTSSv128m128, 2)
TEST_INPUTS(
    0x00000000, 9.00000,        // a "perfect square," of which sqrt() is an integer
    0x12345678, 9.00000,        // doesn't matter what we initialize to dest, as long as we do
    0x00000000, 0.00000,        // sqrt(0) should be 0
    0x00000000, -1.00000,       // should return a constant (the QNaN floating-point indefinite)
    0x00000000, 10.89,         // should be 3.33
//    0x00000000, 9.8,        // a test for sqrt where the result would need to be truncated (fail)
    0x00000000, 0x7fbfffff,      // should return the SNaN converted to a QNaN
    0x00000000, 0xffbfffff,      // should return the -SNaN converted to a -QNaN
    0x00000000, 0x7f800000)      // inf
//    0x00000000, 0xff800000)      // -inf (fail)
    movq xmm0, ARG1_64;
    push ARG2_64;           // load the low single-precision floating point value of m128
    sqrtss xmm0, [rsp];     // find the sqrt of the low SP FP value of [rsp], store in xmm0
TEST_END_64

#if HAS_FEATURE_AVX
//2436 VSQRTSS VSQRTSS_XMMdq_XMMdq_MEMd AVX AVX AVX ATTRIBUTES: MXCSR SIMD_SCALAR 
// 3 
//	0 REG0 EXPLICIT W NT_LOOKUP_FN F32 XMM_R 
//	1 REG1 EXPLICIT R NT_LOOKUP_FN F32 XMM_N 
//	2 MEM0 EXPLICIT R IMM_CONST F32
/*
TEST_BEGIN_64(VSQRTSSv128v128m128, 2)
TEST_INPUTS(
    0x00000000, 9.00000,        // a "perfect square," of which sqrt() is an integer
    0x12345678, 9.00000,        // doesn't matter what we initialize to dest, as long as we do
    0x00000000, 0.00000,        // sqrt(0) should be 0
    0x00000000, -1.00000,       // should return a constant (the QNaN floating-point indefinite)
    0x00000000, 10.89,         // should be 3.33
//    0x00000000, 9.8,        // a test for sqrt where the result would need to be truncated (fail)
    0x00000000, 0x7fbfffff,      // should return the SNaN converted to a QNaN
    0x00000000, 0xffbfffff,      // should return the -SNaN converted to a -QNaN
    0x00000000, 0x7f800000)      // inf
//    0x00000000, 0xff800000)      // -inf (fail)
    push ARG1_64;
    push ARG2_64;                 // load the low single-prec. floating point value of v128 #2
    movq xmm1, qword ptr [rsp+8]; // load the low DWORD of v128 #1
    vsqrtss xmm2, xmm1, [rsp];    // return the sqrt of ?? into ???
TEST_END_64

//2437 VSQRTSS VSQRTSS_XMMdq_XMMdq_XMMd AVX AVX AVX ATTRIBUTES: MXCSR SIMD_SCALAR 
// 3 
//	0 REG0 EXPLICIT W NT_LOOKUP_FN F32 XMM_R 
//	1 REG1 EXPLICIT R NT_LOOKUP_FN F32 XMM_N 
//	2 REG2 EXPLICIT R NT_LOOKUP_FN F32 XMM_B
//TEST_BEGIN_64(VSQRTSSv128v128v128, 2)
//TEST_INPUTS(
    0x00000000, 9.00000,        // a "perfect square," of which sqrt() is an integer
    0x12345678, 9.00000,        // doesn't matter what we initialize to dest, as long as we do
    0x00000000, 0.00000,        // sqrt(0) should be 0
    0x00000000, -1.00000,       // should return a constant (the QNaN floating-point indefinite)
    0x00000000, 10.89,         // should be 3.33
//    0x00000000, 9.8,        // a test for sqrt where the result would need to be truncated (fail)
    0x00000000, 0x7fbfffff,      // should return the SNaN converted to a QNaN
    0x00000000, 0xffbfffff,      // should return the -SNaN converted to a -QNaN
    0x00000000, 0x7f800000)      // inf
//    0x00000000, 0xff800000)      // -inf (fail)
//    push ARG1_64;
//    push ARG2_64;
//    movq xmm0, qword ptr [rsp+8]; // load the low single-prec. floating point value of v128 #1
//    movq xmm1, qword ptr [rsp];   // load the low DWORD of v128 #2
//    vsqrtss xmm2, xmm1, xmm0;     // find the sqrt of ??, store in ???
//TEST_END_64
*/
#endif  // HAS_FEATURE_AVX
