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

#define PSHUFLW_INPUTS_64                                                              \
    0x0000000000000000, 0x0000000000000000, /* sanity check: dest should be be 0's */  \
    0xfedcba9876543210, 0x0000000000000000, /* dest should still hold 0's */           \
    0xfedcba9876543210, 0xffffffffffffffff, /* dest should be all f's */               \
    0x0000000000000000, 0xaaaabbbbccccdddd  /* dest should be shuffled correctly */

// Test multiple shuffles using multiple patterns:
TEST_BEGIN_64(PSHUFLWv128m128i8, 2)
TEST_INPUTS(PSHUFLW_INPUTS_64)
    movq xmm0, ARG1_64;
    movq xmm1, ARG1_64;
    movq xmm2, ARG1_64;
    movq xmm3, ARG1_64;
    push 0;
    push ARG2_64;
    pshuflw xmm0, xmmword ptr [rsp], 0x00;
    pshuflw xmm1, xmmword ptr [rsp], 0x11;
    pshuflw xmm2, xmmword ptr [rsp], 0x55;
    pshuflw xmm3, xmmword ptr [rsp], 0xFF;
TEST_END_64

// No-op case (no re-ordering):
TEST_BEGIN_64(PSHUFLWv128v128i8_00, 2)
TEST_INPUTS(PSHUFLW_INPUTS_64)
    movq xmm4, ARG1_64;   // load the low QWORD of v128 #1
    movq xmm0, ARG2_64;   // load the low QWORD of v128 #2
    pshuflw xmm4, xmm0, 0x00;
TEST_END_64

// Re-order using 0x11 pattern (00010001b)
TEST_BEGIN_64(PSHUFLWv128v128i8_11, 2)
TEST_INPUTS(PSHUFLW_INPUTS_64)
    movq xmm5, ARG1_64;   // load the low QWORD of v128 #1
    movq xmm1, ARG2_64;   // load the low QWORD of v128 #2
    pshuflw xmm5, xmm1, 0x11;
TEST_END_64

// Re-order using 0x55 pattern (01010101b)
TEST_BEGIN_64(PSHUFLWv128v128i8_55, 2)
TEST_INPUTS(PSHUFLW_INPUTS_64)
    movq xmm6, ARG1_64;   // load the low QWORD of v128 #1
    movq xmm2, ARG2_64;   // load the low QWORD of v128 #2
    pshuflw xmm6, xmm2, 0x55;
TEST_END_64

// Re-order using 0xFF pattern (11111111b)
TEST_BEGIN_64(PSHUFLWv128v128i8_FF, 2)
TEST_INPUTS(PSHUFLW_INPUTS_64)
    movq xmm7, ARG1_64;   // load the low QWORD of v128 #1
    movq xmm3, ARG2_64;   // load the low QWORD of v128 #2
    pshuflw xmm7, xmm3, 0xFF;
TEST_END_64


#if HAS_FEATURE_AVX

TEST_BEGIN_64(VPSHUFLWv128m128i8, 2)
TEST_INPUTS(PSHUFLW_INPUTS_64)
    movq xmm0, ARG1_64;
    movq xmm1, ARG1_64;
    movq xmm2, ARG1_64;
    movq xmm3, ARG1_64;
    push 0;
    push ARG2_64;
    vpshuflw xmm0, xmmword ptr [rsp], 0x00;
    vpshuflw xmm1, xmmword ptr [rsp], 0x11;
    vpshuflw xmm2, xmmword ptr [rsp], 0x55;
    vpshuflw xmm3, xmmword ptr [rsp], 0xFF;
TEST_END_64

TEST_BEGIN_64(VPSHUFLWv128v128i8, 2)
TEST_INPUTS(PSHUFLW_INPUTS_64)
    movq xmm4, ARG1_64;
    movq xmm5, ARG1_64;
    movq xmm6, ARG1_64;
    movq xmm7, ARG1_64;
    movq xmm0, ARG2_64;
    movq xmm1, ARG2_64;
    movq xmm2, ARG2_64;
    movq xmm3, ARG2_64;
    vpshuflw xmm4, xmm0, 0x00;
    vpshuflw xmm5, xmm1, 0x11;
    vpshuflw xmm6, xmm2, 0x55;
    vpshuflw xmm7, xmm3, 0xFF;
TEST_END_64

TEST_BEGIN_64(VPSHUFLWv256m256i8, 2)
TEST_INPUTS(PSHUFLW_INPUTS_64)
    push 0;
    push 0;
    push 0;
    push ARG1_64;
    vmovdqu ymm0, [rsp];
    vmovdqu ymm1, [rsp];
    vmovdqu ymm2, [rsp];
    vmovdqu ymm3, [rsp];
    push 0;
    push 0;
    push 0;
    push ARG2_64;
    vpshuflw ymm0, ymmword ptr [rsp], 0x00;
    vpshuflw ymm1, ymmword ptr [rsp], 0x11;
    vpshuflw ymm2, ymmword ptr [rsp], 0x55;
    vpshuflw ymm3, ymmword ptr [rsp], 0xFF;
TEST_END_64

TEST_BEGIN_64(VPSHUFLWv256v256i8, 2)
TEST_INPUTS(PSHUFLW_INPUTS_64)
    push 0;
    push 0;
    push 0;
    push ARG1_64;
    vmovdqu ymm4, ymmword ptr [rsp];
    vmovdqu ymm5, ymmword ptr [rsp];
    vmovdqu ymm6, ymmword ptr [rsp];
    vmovdqu ymm7, ymmword ptr [rsp];
    push 0;
    push 0;
    push 0;
    push ARG2_64;
    vmovdqu ymm0, ymmword ptr [rsp];
    vmovdqu ymm1, ymmword ptr [rsp];
    vmovdqu ymm2, ymmword ptr [rsp];
    vmovdqu ymm3, ymmword ptr [rsp];
    vpshuflw ymm4, ymm0, 0x00;
    vpshuflw ymm5, ymm1, 0x11;
    vpshuflw ymm6, ymm2, 0x55;
    vpshuflw ymm7, ymm3, 0xFF;
TEST_END_64

#endif  // HAS_FEATURE_AVX