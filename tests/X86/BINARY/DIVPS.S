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

TEST_BEGIN(DIVPSv128v128_40, 1)
TEST_INPUTS(0)
    divps xmm4, xmm0
TEST_END

TEST_BEGIN(DIVPSv128v128_45, 1)
TEST_INPUTS(0)
    divps xmm4, xmm5
TEST_END

#if APPLE_SAFE_TESTS

TEST_BEGIN(DIVPSv128m128_40, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm0
    divps xmm4, [rsp - 16]
TEST_END

TEST_BEGIN(DIVPSv128m128_45, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm5
    divps xmm4, [rsp - 16]
TEST_END

#endif

#if HAS_FEATURE_AVX
TEST_BEGIN(VDIVPSv128v128_40, 1)
TEST_INPUTS(0)
    vdivps xmm0, xmm4, xmm0
TEST_END

TEST_BEGIN(VDIVPSv128v128_45, 1)
TEST_INPUTS(0)
    vdivps xmm1, xmm4, xmm5
TEST_END

TEST_BEGIN(VDIVPSv256v256_40, 1)
TEST_INPUTS(0)
    vdivps ymm0, ymm4, ymm0
TEST_END

TEST_BEGIN(VDIVPSv256v256_45, 1)
TEST_INPUTS(0)
    vdivps ymm1, ymm4, ymm5
TEST_END

#if APPLE_SAFE_TESTS
TEST_BEGIN(VDIVPSv128m128_45, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm5
    vdivps xmm1, xmm4, [rsp - 16]
TEST_END

TEST_BEGIN(VDIVPSv256m256_45, 1)
TEST_INPUTS(0)
    vmovdqu [rsp - 32], ymm5
    vdivps ymm1, ymm4, [rsp - 32]
TEST_END
#endif  // APPLE_SAFE_TESTS
#endif
