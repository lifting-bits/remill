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

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VINSERTF128_imm00, 3)
TEST_INPUTS(
    0x7ff8000012345678,0x0123456789abcdef,0xfedcba9876543210,
    0x7ff8000012345678,0x1111222233334444,0x5555666677778888
)
    push 0;
    push ARG2_64;
    push 0;
    push ARG3_64;
    vmovdqu ymm2, [rsp];
    movq xmm3, ARG1_64;
    vinsertf128 ymm1, ymm2, xmm3, 0;
TEST_END_64

TEST_BEGIN_64(VINSERTF128_imm01, 3)
TEST_INPUTS(
    0x7ff8000012345678,0x0123456789abcdef,0xfedcba9876543210,
    0x7ff8000012345678,0x1111222233334444,0x5555666677778888
)
    push 0;
    push ARG2_64;
    push 0;
    push ARG3_64;
    vmovdqu ymm2, [rsp];
    movq xmm3, ARG1_64;
    vinsertf128 ymm1, ymm2, xmm3, 1;
TEST_END_64

TEST_BEGIN_64(VINSERTF128_imm10, 3)
TEST_INPUTS(
    0x7ff8000012345678,0x0123456789abcdef,0xfedcba9876543210,
    0x7ff8000012345678,0x1111222233334444,0x5555666677778888
)
    push 0;
    push ARG2_64;
    push 0;
    push ARG3_64;
    vmovdqu ymm2, [rsp];
    movq xmm3, ARG1_64;
    vinsertf128 ymm1, ymm2, xmm3, 2;
TEST_END_64

TEST_BEGIN_64(VINSERTF128_imm11, 3)
TEST_INPUTS(
    0x7ff8000012345678,0x0123456789abcdef,0xfedcba9876543210,
    0x7ff8000012345678,0x1111222233334444,0x5555666677778888
)
    push 0;
    push ARG2_64;
    push 0;
    push ARG3_64;
    vmovdqu ymm2, [rsp];
    movq xmm3, ARG1_64;
    vinsertf128 ymm1, ymm2, xmm3, 3;
TEST_END_64

#endif  // HAS_FEATURE_AVX
