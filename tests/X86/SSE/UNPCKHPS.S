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

#define UNPCKHPS_INPUTS_64 \
    0x0000000000000000, 0x0000000000000000,  /* sanity check */\
    0xfedcba9876543210, 0x0000000000000000,  /* arbitrarily chosen values */\
    0xfedcba9876543210, 0xffffffffffffffff   /* other arbitrarily chosen values */

TEST_BEGIN_64(UNPCKHPSv128v128, 2)
TEST_INPUTS(UNPCKHPS_INPUTS_64)
    push ARG1_64;
    movhps xmm0, qword ptr [rsp];
    push ARG2_64;
    movhps xmm1, qword ptr [rsp];
    unpckhps xmm0, xmm1;
TEST_END_64

TEST_BEGIN_64(UNPCKHPSv128m128, 2)
TEST_INPUTS(UNPCKHPS_INPUTS_64)
    push ARG1_64;
    movhps xmm0, qword ptr [rsp];
    push ARG2_64;
    push ARG2_64;
    unpckhps xmm0, xmmword ptr [rsp+8];
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VUNPCKHPSv128v128m128, 2)
TEST_INPUTS(UNPCKHPS_INPUTS_64)
    push ARG1_64;
    movhps xmm1, qword ptr [rsp];
    push ARG2_64;
    push ARG2_64;
    vunpckhps xmm0, xmm1, xmmword ptr [rsp+8];
TEST_END_64

TEST_BEGIN_64(VUNPCKHPSv128v128v128, 2)
TEST_INPUTS(UNPCKHPS_INPUTS_64)
    push ARG1_64;
    movhps xmm1, qword ptr [rsp];
    push ARG2_64;
    movhps xmm2, qword ptr [rsp];
    vunpckhps xmm0, xmm1, xmm2;
TEST_END_64

#endif
