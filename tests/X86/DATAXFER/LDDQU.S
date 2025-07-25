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

#if APPLE_SAFE_TESTS
TEST_BEGIN(LDDQUv128m128, 1)
TEST_INPUTS(
    0)
    lddqu xmm0, [rsp - 16]
TEST_END

TEST_BEGIN(LDDQUv128m128_4, 1)
TEST_INPUTS(
    0)
    lddqu xmm4, [rsp - 16]
TEST_END
#endif  // APPLE_SAFE_TESTS

#if HAS_FEATURE_AVX
#if APPLE_SAFE_TESTS
TEST_BEGIN(VLDDQUv128m128, 1)
TEST_INPUTS(
    0)
    vlddqu xmm0, [rsp - 16]
TEST_END

TEST_BEGIN(VLDDQUv128m128_4, 1)
TEST_INPUTS(
    0)
    vlddqu xmm4, [rsp - 16]
TEST_END

TEST_BEGIN(VLDDQUv256m256, 1)
TEST_INPUTS(
    0)
    vlddqu ymm0, [rsp - 32]
TEST_END

TEST_BEGIN(VLDDQUv256m256, 1)
TEST_INPUTS(
    0)
    vlddqu ymm4, [rsp - 32]
TEST_END
#endif  // APPLE_SAFE_TESTS

#endif  // HAS_FEATURE_AVX
