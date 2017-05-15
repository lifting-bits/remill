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

TEST_BEGIN_64(CVTPD2PSv128m128, 2)
TEST_INPUTS(
    0x0010000000000000,  // std::numeric_limits<double>::min()
    0x7fefffffffffffff,  // std::numeric_limits<double>::max()
    0x0,  // 0
    0x3fe0000000000000,  // 0.5
    0xbfe0000000000000,  // -0.5
    0x3ff0000000000000,  // 1.0
    0xbff0000000000000,  // -1.0
    0x4058ff5c28f5c28f,  // 99.99
    0xc058ff5c28f5c28f,  // -99.99
    0x0)

    push ARG1_64
    push ARG2_64
    cvtpd2ps xmm0, XMMWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(CVTPD2PSv128v128, 2)
TEST_INPUTS(
    0x10000000000000,  // std::numeric_limits<double>::min()
    0x7fefffffffffffff,  // std::numeric_limits<double>::max()
    0x0,  // 0
    0x3fe0000000000000,  // 0.5
    0xbfe0000000000000,  // -0.5
    0x3ff0000000000000,  // 1.0
    0xbff0000000000000,  // -1.0
    0x4058ff5c28f5c28f,  // 99.99
    0xc058ff5c28f5c28f,  // -99.99
    0)

    push ARG1_64
    push ARG2_64
    movdqu xmm4, [rsp]
    cvtpd2ps xmm0, xmm4
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VCVTPD2PSv128m128, 2)
TEST_INPUTS(
    0x10000000000000,  // std::numeric_limits<double>::min()
    0x7fefffffffffffff,  // std::numeric_limits<double>::max()
    0x0,  // 0
    0x3fe0000000000000,  // 0.5
    0xbfe0000000000000,  // -0.5
    0x3ff0000000000000,  // 1.0
    0xbff0000000000000,  // -1.0
    0x4058ff5c28f5c28f,  // 99.99
    0xc058ff5c28f5c28f,  // -99.99
    0)

    push ARG1_64
    push ARG2_64
    .byte 0xc5, 0xfb, 0xe6, 0x04, 0x24  // vcvtpd2ps xmm0, XMMWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(VCVTPD2PSv128v128, 2)
TEST_INPUTS(
    0x10000000000000,  // std::numeric_limits<double>::min()
    0x7fefffffffffffff,  // std::numeric_limits<double>::max()
    0x0,  // 0
    0x3fe0000000000000,  // 0.5
    0xbfe0000000000000,  // -0.5
    0x3ff0000000000000,  // 1.0
    0xbff0000000000000,  // -1.0
    0x4058ff5c28f5c28f,  // 99.99
    0xc058ff5c28f5c28f,  // -99.99
    0)

    push ARG1_64
    push ARG2_64
    movdqu xmm4, XMMWORD PTR [rsp]
    vcvtpd2ps xmm0, xmm4
TEST_END_64


TEST_BEGIN_64(VCVTPD2PSv128m256, 2)
TEST_INPUTS(
    0x10000000000000,  // std::numeric_limits<double>::min()
    0x7fefffffffffffff,  // std::numeric_limits<double>::max()
    0x0,  // 0
    0x3fe0000000000000,  // 0.5
    0xbfe0000000000000,  // -0.5
    0x3ff0000000000000,  // 1.0
    0xbff0000000000000,  // -1.0
    0x4058ff5c28f5c28f,  // 99.99
    0xc058ff5c28f5c28f,  // -99.99
    0)

    push ARG1_64
    push ARG2_64
    push ARG1_64
    push ARG2_64
    vcvtpd2ps xmm0, YMMWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(VCVTPD2PSv128v256, 2)
TEST_INPUTS(
    0x10000000000000,  // std::numeric_limits<double>::min()
    0x7fefffffffffffff,  // std::numeric_limits<double>::max()
    0x0,  // 0
    0x3fe0000000000000,  // 0.5
    0xbfe0000000000000,  // -0.5
    0x3ff0000000000000,  // 1.0
    0xbff0000000000000,  // -1.0
    0x4058ff5c28f5c28f,  // 99.99
    0xc058ff5c28f5c28f,  // -99.99
    0)

    push ARG1_64
    push ARG2_64
    push ARG1_64
    push ARG2_64
    vmovdqu ymm4, YMMWORD PTR [rsp]
    vcvtpd2ps xmm0, ymm4
TEST_END_64

#endif  // HAS_FEATURE_AVX
