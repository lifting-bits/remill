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

TEST_BEGIN(MOVAPDv128v128_1to0, 1)
TEST_INPUTS(
    0)
    movapd xmm4, xmm0
TEST_END

TEST_BEGIN(MOVAPDv128v128_0to1, 1)
TEST_INPUTS(
    0)
    movapd xmm0, xmm4
TEST_END

#if APPLE_SAFE_TESTS
TEST_BEGIN(MOVAPDv128m128, 1)
TEST_INPUTS(
    0)
    movapd xmm0, [rsp - 128]
TEST_END

TEST_BEGIN(MOVAPDv128m128_4, 1)
TEST_INPUTS(
    0)
    movapd xmm4, [rsp - 128]
TEST_END
#endif  // APPLE_SAFE_TESTS

#if HAS_FEATURE_AVX

TEST_BEGIN(VMOVAPDv128v128_1to0, 1)
TEST_INPUTS(
    0)
    vmovapd xmm4, xmm0
TEST_END

TEST_BEGIN(VMOVAPDv128v128_0to1, 1)
TEST_INPUTS(
    0)
    vmovapd xmm0, xmm4
TEST_END

TEST_BEGIN(VMOVAPDv256v256_1to0, 1)
TEST_INPUTS(
    0)
    vmovapd ymm4, ymm0
TEST_END

TEST_BEGIN(VMOVAPDv256v256_0to1, 1)
TEST_INPUTS(
    0)
    vmovapd ymm0, ymm4
TEST_END

#if APPLE_SAFE_TESTS
TEST_BEGIN(VMOVAPDv128m128, 1)
TEST_INPUTS(
    0)
    vmovapd xmm0, [rsp - 128]
TEST_END

TEST_BEGIN(VMOVAPDv128m128_4, 1)
TEST_INPUTS(
    0)
    vmovapd xmm4, [rsp - 128]
TEST_END

TEST_BEGIN(VMOVAPDv256m256, 1)
TEST_INPUTS(
    0)
    vmovapd ymm0, [rsp - 128]
TEST_END

TEST_BEGIN(VMOVAPDv256m256_4, 1)
TEST_INPUTS(
    0)
    vmovapd ymm4, [rsp - 128]
TEST_END
#endif  // APPLE_SAFE_TESTS
#endif  // HAS_FEATURE_AVX
