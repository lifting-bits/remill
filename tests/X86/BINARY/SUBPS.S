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

TEST_BEGIN(SUBPSv128v128_04, 1)
TEST_INPUTS(0)
    subps xmm0, xmm4
TEST_END

TEST_BEGIN(SUBPSv128v128_40, 1)
TEST_INPUTS(0)
    subps xmm4, xmm0
TEST_END

#if APPLE_SAFE_TESTS

TEST_BEGIN(SUBPSv128m128_04, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm4
    subps xmm0, [rsp - 16]
TEST_END

TEST_BEGIN(SUBPSv128m128_40, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm0
    subps xmm4, [rsp - 16]
TEST_END

#endif  // APPLE_SAFE_TESTS

#if HAS_FEATURE_AVX
TEST_BEGIN(VSUBPSv128v128_04, 1)
TEST_INPUTS(0)
    vsubps xmm0, xmm1, xmm4
TEST_END

TEST_BEGIN(VSUBPSv128v128_40, 1)
TEST_INPUTS(0)
    vsubps xmm1, xmm4, xmm0
TEST_END

TEST_BEGIN(VSUBPSv256v256_04, 1)
TEST_INPUTS(0)
    vsubps ymm0, ymm1, ymm4
TEST_END

TEST_BEGIN(VSUBPSv256v256_40, 1)
TEST_INPUTS(0)
    vsubps ymm1, ymm4, ymm0
TEST_END

#if APPLE_SAFE_TESTS
TEST_BEGIN(VSUBPSv128m128_40, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm0
    vsubps xmm1, xmm4, [rsp - 16]
TEST_END

TEST_BEGIN(VSUBPSv256m256_40, 1)
TEST_INPUTS(0)
    vmovdqu [rsp - 32], ymm0
    vsubps ymm1, ymm4, [rsp - 32]
TEST_END
#endif  // APPLE_SAFE_TESTS
#endif  // HAS_FEATURE_AVX
