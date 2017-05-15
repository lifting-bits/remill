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

TEST_BEGIN_64(CVTTPS2DQv128m128, 2)
TEST_INPUTS(
    0x7f7fffff00800000,  // std::numeric_limits<double>::min(), max
    0x0080000000000000,  // std::numeric_limits<double>::max(), 0
    0x000000003f000000,  // 0, 0.5
    0x3f000000bf000000,  // 0.5, -0.5
    0xbf0000003f800000,  // -0.5, 1.0
    0x3f800000bf800000,  // 1.0, -1.0
    0xbff0000047c34fc0)  // -1.0, 99999.5

    push ARG1_64
    push ARG2_64
    cvttps2dq xmm0, XMMWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(CVTTPS2DQv128v128, 2)
TEST_INPUTS(
    0x7f7fffff00800000,  // std::numeric_limits<double>::min(), max
    0x0080000000000000,  // std::numeric_limits<double>::max(), 0
    0x000000003f000000,  // 0, 0.5
    0x3f000000bf000000,  // 0.5, -0.5
    0xbf0000003f800000,  // -0.5, 1.0
    0x3f800000bf800000,  // 1.0, -1.0
    0xbff0000047c34fc0)  // -1.0, 99999.5

    push ARG1_64
    push ARG2_64
    movdqu xmm4, [rsp]
    cvttps2dq xmm0, xmm4
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VCVTTPS2DQv128m128, 2)
TEST_INPUTS(
    0x7f7fffff00800000,  // std::numeric_limits<double>::min(), max
    0x0080000000000000,  // std::numeric_limits<double>::max(), 0
    0x000000003f000000,  // 0, 0.5
    0x3f000000bf000000,  // 0.5, -0.5
    0xbf0000003f800000,  // -0.5, 1.0
    0x3f800000bf800000,  // 1.0, -1.0
    0xbff0000047c34fc0)  // -1.0, 99999.5

    push ARG1_64
    push ARG2_64
    vcvttps2dq xmm0, XMMWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(VCVTTPS2DQv128v128, 2)
TEST_INPUTS(
    0x7f7fffff00800000,  // std::numeric_limits<double>::min(), max
    0x0080000000000000,  // std::numeric_limits<double>::max(), 0
    0x000000003f000000,  // 0, 0.5
    0x3f000000bf000000,  // 0.5, -0.5
    0xbf0000003f800000,  // -0.5, 1.0
    0x3f800000bf800000,  // 1.0, -1.0
    0xbff0000047c34fc0)  // -1.0, 99999.5

    push ARG1_64
    push ARG2_64
    movdqu xmm4, XMMWORD PTR [rsp]
    vcvttps2dq xmm0, xmm4
TEST_END_64


TEST_BEGIN_64(VCVTTPS2DQv256m256, 2)
TEST_INPUTS(
    0x7f7fffff00800000,  // std::numeric_limits<double>::min(), max
    0x0080000000000000,  // std::numeric_limits<double>::max(), 0
    0x000000003f000000,  // 0, 0.5
    0x3f000000bf000000,  // 0.5, -0.5
    0xbf0000003f800000,  // -0.5, 1.0
    0x3f800000bf800000,  // 1.0, -1.0
    0xbff0000047c34fc0)  // -1.0, 99999.5

    push ARG1_64
    push ARG2_64
    push ARG1_64
    push ARG2_64
    vcvttps2dq ymm0, YMMWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(VCVTTPS2DQv256v256, 2)
TEST_INPUTS(
    0x7f7fffff00800000,  // std::numeric_limits<double>::min(), max
    0x0080000000000000,  // std::numeric_limits<double>::max(), 0
    0x000000003f000000,  // 0, 0.5
    0x3f000000bf000000,  // 0.5, -0.5
    0xbf0000003f800000,  // -0.5, 1.0
    0x3f800000bf800000,  // 1.0, -1.0
    0xbff0000047c34fc0)  // -1.0, 99999.5

    push ARG1_64
    push ARG2_64
    push ARG1_64
    push ARG2_64
    vmovdqu ymm4, YMMWORD PTR [rsp]
    vcvttps2dq ymm0, ymm4
TEST_END_64

#endif  // HAS_FEATURE_AVX
