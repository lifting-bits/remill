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

/* NOTE:
 * YMM0 - YMM3 are filled will 0xFF.
 * YMM4 and on are filled with 0x0. */

TEST_BEGIN(MOVUPDv128v128_1to0, 1)
TEST_INPUTS(
    0)
    movupd xmm4, xmm0
TEST_END

TEST_BEGIN(MOVUPDv128v128_0to1, 1)
TEST_INPUTS(
    0)
    movupd xmm0, xmm4
TEST_END

#if APPLE_SAFE_TESTS

TEST_BEGIN_64(MOVUPDv128m128_64, 1)
TEST_INPUTS(0)
    movupd xmm0, [rsp - 16]
TEST_END_64

TEST_BEGIN_64(MOVUPDv128m128_1_64, 1)
TEST_INPUTS(0)
    movupd xmm4, [rsp - 16]
TEST_END_64

#endif  // APPLE_SAFE_TESTS

#if HAS_FEATURE_AVX

TEST_BEGIN(VMOVUPDv128v128_1to0, 1)
TEST_INPUTS(
    0)
    vmovupd xmm4, xmm0
TEST_END

TEST_BEGIN(VMOVUPDv128v128_0to1, 1)
TEST_INPUTS(
    0)
    vmovupd xmm0, xmm4
TEST_END

TEST_BEGIN(VMOVUPDv256v256_1to0, 1)
TEST_INPUTS(
    0)
    vmovupd ymm4, ymm0
TEST_END

TEST_BEGIN(VMOVUPDv256v256_0to1, 1)
TEST_INPUTS(
    0)
    vmovupd ymm0, ymm4
TEST_END


#if APPLE_SAFE_TESTS

TEST_BEGIN_64(VMOVUPDv128m128_64, 1)
TEST_INPUTS(0)
    vmovupd xmm0, [rsp - 16]
TEST_END_64

TEST_BEGIN_64(VMOVUPDv128m128_1_64, 1)
TEST_INPUTS(0)
    vmovupd xmm4, [rsp - 16]
TEST_END_64

TEST_BEGIN_64(VMOVUPDv256m256_64, 1)
TEST_INPUTS(0)
    vmovupd ymm0, [rsp - 32]
TEST_END_64

TEST_BEGIN_64(VMOVUPDv128m256_1_64, 1)
TEST_INPUTS(0)
    vmovupd ymm4, [rsp - 32]
TEST_END_64

#endif  // APPLE_SAFE_TESTS

#endif  // HAS_FEATURE_AVX
