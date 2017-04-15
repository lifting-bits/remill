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

TEST_BEGIN(MOVLPDv128m64, 1)
TEST_INPUTS(
    0)
    movlpd xmm0,QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(MOVLPDv128m64_4, 1)
TEST_INPUTS(
    0)
    movlpd xmm4,QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(MOVLPDm64v128, 1)
TEST_INPUTS(
    0)
    movlpd QWORD PTR [rsp - 8], xmm0
TEST_END

TEST_BEGIN(MOVLPDm64v128_4, 1)
TEST_INPUTS(
    0)
    movlpd QWORD PTR [rsp - 8], xmm4
TEST_END

#if HAS_FEATURE_AVX

TEST_BEGIN(VMOVLPDv128m64, 1)
TEST_INPUTS(
    0)
    vmovlpd xmm0, xmm1, QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(VMOVLPDv128m64_4, 1)
TEST_INPUTS(
    0)
    vmovlpd xmm4, xmm1, QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(VMOVLPDm64v128, 1)
TEST_INPUTS(
    0)
    vmovlpd QWORD PTR [rsp - 8], xmm0
TEST_END

TEST_BEGIN(VMOVLPDm64v128_4, 1)
TEST_INPUTS(
    0)
    vmovlpd QWORD PTR [rsp - 8], xmm4
TEST_END

#endif  // HAS_FEATURE_AVX
#endif  // APPLE_SAFE_TESTS
