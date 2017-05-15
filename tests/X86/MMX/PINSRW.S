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

TEST_BEGIN_64(PINSRWv64r32i8_0, 2)
TEST_INPUTS(
    0, 0,
    0, 0x4141,
    0, 0x41410000)

    movq mm0, ARG1_64
    pinsrw mm0, ARG2_32, 0
TEST_END_64

TEST_BEGIN_64(PINSRWv64r32i8_1, 2)
TEST_INPUTS(
    0, 0,
    0, 0x4141,
    0, 0x41410000)

    movq mm0, ARG1_64
    pinsrw mm0, ARG2_32, 1
TEST_END_64

TEST_BEGIN_64(PINSRWv64r32i8_7, 2)
TEST_INPUTS(
    0, 0,
    0, 0x4141,
    0, 0x41410000)

    movq mm0, ARG1_64
    pinsrw mm0, ARG2_32, 7
TEST_END_64

TEST_BEGIN_64(PINSRWv64r32i8_8, 2)
TEST_INPUTS(
    0, 0,
    0, 0x4141,
    0, 0x41410000)

    movq mm0, ARG1_64
    pinsrw mm0, ARG2_32, 8
TEST_END_64


TEST_BEGIN_64(PINSRWv128r32i8_0_0, 2)
TEST_INPUTS(
    0, 0,
    0, 0x4141,
    0, 0x41410000)

    movq xmm0, ARG1_64
    pinsrw xmm0, ARG2_32, 0
TEST_END_64

TEST_BEGIN_64(PINSRWv128r32i8_0_1, 2)
TEST_INPUTS(
    0, 0,
    0, 0x4141,
    0, 0x41410000)

    movq xmm0, ARG1_64
    pinsrw xmm0, ARG2_32, 1
TEST_END_64

TEST_BEGIN_64(PINSRWv128r32i8_0_15, 2)
TEST_INPUTS(
    0, 0,
    0, 0x4141,
    0, 0x41410000)

    movq xmm0, ARG1_64
    pinsrw xmm0, ARG2_32, 15
TEST_END_64

TEST_BEGIN_64(PINSRWv128r32i8_0_16, 2)
TEST_INPUTS(
    0, 0,
    0, 0x4141,
    0, 0x41410000)

    movq xmm0, ARG1_64
    pinsrw xmm0, ARG2_32, 16
TEST_END_64


TEST_BEGIN_64(PINSRWv128r32i8_4_0, 2)
TEST_INPUTS(
    0, 0,
    0, 0x4141,
    0, 0x41410000)

    movq xmm4, ARG1_64
    pinsrw xmm4, ARG2_32, 0
TEST_END_64

TEST_BEGIN_64(PINSRWv128r32i8_4_1, 2)
TEST_INPUTS(
    0, 0,
    0, 0x4141,
    0, 0x41410000)

    movq xmm4, ARG1_64
    pinsrw xmm4, ARG2_32, 1
TEST_END_64

TEST_BEGIN_64(PINSRWv128r32i8_4_15, 2)
TEST_INPUTS(
    0, 0,
    0, 0x4141,
    0, 0x41410000)

    movq xmm4, ARG1_64
    pinsrw xmm4, ARG2_32, 15
TEST_END_64

TEST_BEGIN_64(PINSRWv128r32i8_4_16, 2)
TEST_INPUTS(
    0, 0,
    0, 0x4141,
    0, 0x41410000)

    movq xmm4, ARG1_64
    pinsrw xmm4, ARG2_32, 16
TEST_END_64


#if HAS_FEATURE_AVX

TEST_BEGIN_64(VPINSRWv128r32i8_0, 2)
TEST_INPUTS(
    0, 0,
    0, 0x4141,
    0, 0x41410000)

    movq xmm0, ARG1_64
    vpinsrw xmm4, xmm0, ARG2_32, 0
TEST_END_64

TEST_BEGIN_64(VPINSRWv128r32i8_1, 2)
TEST_INPUTS(
    0, 0,
    0, 0x4141,
    0, 0x41410000)

    movq xmm0, ARG1_64
    vpinsrw xmm4, xmm0, ARG2_32, 1
TEST_END_64

TEST_BEGIN_64(VPINSRWv128r32i8_7, 2)
TEST_INPUTS(
    0, 0,
    0, 0x4141,
    0, 0x41410000)

    movq xmm0, ARG1_64
    vpinsrw xmm4, xmm0, ARG2_32, 7
TEST_END_64

TEST_BEGIN_64(VPINSRWv128r32i8_15, 2)
TEST_INPUTS(
    0, 0,
    0, 0x4141,
    0, 0x41410000)

    movq xmm0, ARG1_64
    vpinsrw xmm4, xmm0, ARG2_32, 15
TEST_END_64

TEST_BEGIN_64(VPINSRWv128r32i8_0_16, 2)
TEST_INPUTS(
    0, 0,
    0, 0x4141,
    0, 0x41410000)

    movq xmm0, ARG1_64
    vpinsrw xmm4, xmm0, ARG2_32, 16
TEST_END_64

#endif  // HAS_FEATURE_AVX
