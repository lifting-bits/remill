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

#define UNPCKHPD_INPUTS_64 \
    0x0000000000000000, 0x0000000000000000,  /* sanity check */\
    0xfedcba9876543210, 0x0000000000000000,  /* arbitrarily chosen values */\
    0xfedcba9876543210, 0xffffffffffffffff   /* other arbitrarily chosen values */\
    
TEST_BEGIN_64(UNPCKHPDv128v128, 2)
TEST_INPUTS(UNPCKHPD_INPUTS_64)
    push ARG1_64;
    movhpd xmm0, qword ptr [rsp];     // dest[127:64]<-arg1[63:0]
    push ARG2_64;
    movhpd xmm1, qword ptr [rsp];     // src[127:64]<-arg2[63:0]
    unpckhpd xmm0, xmm1;    // dest[63:0]<-dest[127:64], then dest[127:64]<-src[127:64]
TEST_END_64

TEST_BEGIN_64(UNPCKHPDv128m128, 2)
TEST_INPUTS(UNPCKHPD_INPUTS_64)
    push ARG1_64;
    movhpd xmm0, qword ptr [rsp];    // dest[127:64]<-arg1[63:0]
    push ARG2_64;                    // src[127:64]<-arg2[63:0]
    push ARG2_64;                    // src[63:0]<-arg2[63:0]. This is just to align the last push.
    unpckhpd xmm0, xmmword ptr [rsp+8];  // dest[63:0]<-dest[127:64], then dest[127:64]<-src[127:64]
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VUNPCKHPDv128v128m128, 2)
TEST_INPUTS(UNPCKHPD_INPUTS_64)
    push ARG1_64;
    movhpd xmm1, qword ptr [rsp];    // src1[127:64]<-arg1[63:0]
    push ARG2_64;                    // src2[127:64]<-arg2[63:0]
    push ARG2_64;                    // src2[63:0]<-arg2[63:0]. This is just to align the last push.
    vunpckhpd xmm0, xmm1, xmmword ptr [rsp+8]; // dest[63:0]<-src1[127:64], dest[127:64]<-src2[127:64]
TEST_END_64

TEST_BEGIN_64(VUNPCKHPDv128v128v128, 2)
TEST_INPUTS(UNPCKHPD_INPUTS_64)
    push ARG1_64;
    movhpd xmm1, qword ptr [rsp];     // src1[127:64]<-arg1[63:0]
    push ARG2_64;
    movhpd xmm2, qword ptr [rsp];     // src2[127:64]<-arg2[63:0]
    vunpckhpd xmm0, xmm1, xmm2; // dest[63:0]<-src1[127:64], then dest[127:64]<-src2[127:64]
TEST_END_64

#endif
