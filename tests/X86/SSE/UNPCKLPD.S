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

#define UNPCKLPD_INPUTS_64 \
    0x0000000000000000, 0x0000000000000000,  /* sanity check */\
    0xfedcba9876543210, 0x0000000000000000,  /* arbitrarily chosen values */\
    0xfedcba9876543210, 0xffffffffffffffff   /* other arbitrarily chosen values */\
 
TEST_BEGIN_64(UNPCKLPDv128v128, 2)
TEST_INPUTS(UNPCKLPD_INPUTS_64)
    movq xmm0, ARG1_64;   // load the low QWORD of v128 #1
    movq xmm1, ARG2_64;   // load the low QWORD of v128 #2
    unpcklpd xmm0, xmm1;  // "unpacks and interleaves" the low QWORD values of #1,#2
TEST_END_64

TEST_BEGIN_64(UNPCKLPDv128m128, 2)
TEST_INPUTS(UNPCKLPD_INPUTS_64)
    movq xmm0, ARG1_64;   // load the low QWORD of v128
    push ARG2_64;         // load the low QWORD of m128
    push ARG2_64;         // also, load something as filler for the high QWORD of m128
    unpcklpd xmm0, xmmword ptr [rsp]; // "unpacks and interleaves" the low QWORD values of v128,m128
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VUNPCKLPDv128v128m128, 2)
TEST_INPUTS(UNPCKLPD_INPUTS_64)
    push ARG1_64;                  // load the low QWORD of m128
    push ARG1_64;                  // also, load another QWORD of filler to pad out m128
    push ARG2_64;                  // load the low QWORD of v128 (step 1)
    movq xmm1, qword ptr [rsp];    // load the low QWORD of v128 (step 2)
    vunpcklpd xmm2, xmm1, xmmword ptr [rsp+8]; // "unpacks and interleaves" v128 and m128 into xmm2
TEST_END_64

TEST_BEGIN_64(VUNPCKLPDv128v128v128, 2)
TEST_INPUTS(UNPCKLPD_INPUTS_64)
    push ARG1_64;
    push ARG2_64;
    movq xmm0, qword ptr [rsp+8]; // load the low QWORD of v128 #1
    movq xmm1, qword ptr [rsp];   // load the low QWORD of v128 #2
    vunpcklpd xmm2, xmm1, xmm0;   // "unpacks and interleaves" #1 and #2 into xmm2
TEST_END_64

#endif
