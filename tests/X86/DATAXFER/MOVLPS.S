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

#if APPLE_SAFE_TESTS

TEST_BEGIN(MOVLPSv128m64, 1)
TEST_INPUTS(
    0)
    movlps xmm0,QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(MOVLPSv128m64_4, 1)
TEST_INPUTS(
    0)
    movlps xmm4, QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(MOVLPSm64v128, 1)
TEST_INPUTS(
    0)
    movlps QWORD PTR [rsp - 8], xmm0
TEST_END

TEST_BEGIN(MOVLPSm64v128_4, 1)
TEST_INPUTS(
    0)
    movlps QWORD PTR [rsp - 8], xmm4
TEST_END

#if HAS_FEATURE_AVX

TEST_BEGIN(VMOVLPSvv128v128m64_0_1, 1)
TEST_INPUTS(
    0,
    0x3de353f8,
    0x411ffbe73de353f8)
    vmovlps xmm0, xmm1, QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(VMOVLPSvv128v128m64_4_1, 1)
TEST_INPUTS(
    0,
    0x3de353f8,
    0x411ffbe73de353f8)
    vmovlps xmm4, xmm1, QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(VMOVLPSvv128v128m64_1_4, 1)
TEST_INPUTS(
    0,
    0x3de353f8,
    0x411ffbe73de353f8)
    vmovlps xmm1, xmm4, QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(VMOVLPSm64v128, 1)
TEST_INPUTS(
    0)
    vmovlps QWORD PTR [rsp - 8], xmm0
TEST_END

TEST_BEGIN(VMOVLPSm64v128_4, 1)
TEST_INPUTS(
    0)
    vmovlps QWORD PTR [rsp - 8], xmm4
TEST_END

#endif  // HAS_FEATURE_AVX
#endif  // APPLE_SAFE_TESTS
