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

TEST_BEGIN(CVTDQ2PSv128m128_0, 1)
TEST_INPUTS(0)
    cvtdq2ps xmm0, XMMWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(CVTDQ2PSv128m128_4, 1)
TEST_INPUTS(0)
    cvtdq2ps xmm4, XMMWORD PTR [rsp - 8]
TEST_END

#endif  // APPLE_SAFE_TESTS

TEST_BEGIN(CVTDQ2PSv128v128_0, 1)
TEST_INPUTS(0)
    cvtdq2pd xmm0, xmm4
TEST_END

TEST_BEGIN(CVTDQ2PSv128v128_4, 1)
TEST_INPUTS(0)
    cvtdq2pd xmm4, xmm0
TEST_END

#if HAS_FEATURE_AVX

TEST_BEGIN_MEM(VCVTDQ2PSv128m128_0, 1)
TEST_INPUTS(0)
    vcvtdq2ps xmm0, XMMWORD PTR [rsp - 16]
TEST_END_MEM

TEST_BEGIN_MEM(VCVTDQ2PSv128m128_4, 1)
TEST_INPUTS(0)
    vcvtdq2ps xmm4, XMMWORD PTR [rsp - 16]
TEST_END_MEM

TEST_BEGIN(VCVTDQ2PSv128v128_0, 1)
TEST_INPUTS(0)
    vcvtdq2ps xmm0, xmm4
TEST_END

TEST_BEGIN(VCVTDQ2PSv128v128_4, 1)
TEST_INPUTS(0)
    vcvtdq2ps xmm4, xmm0
TEST_END

TEST_BEGIN_MEM(VCVTDQ2PSv256m256_0, 1)
TEST_INPUTS(0)
    vcvtdq2ps ymm0, YMMWORD PTR [rsp - 32]
TEST_END_MEM

TEST_BEGIN_MEM(VCVTDQ2PSv256m256_1, 1)
TEST_INPUTS(0)
    vcvtdq2ps ymm4, YMMWORD PTR [rsp - 32]
TEST_END_MEM

TEST_BEGIN(VCVTDQ2PSv256v256_0, 1)
TEST_INPUTS(0)
    vcvtdq2ps ymm0, ymm4
TEST_END

TEST_BEGIN(VCVTDQ2PSv256v256_4, 1)
TEST_INPUTS(0)
    vcvtdq2ps ymm4, ymm0
TEST_END

#endif  // HAS_FEATURE_AVX
