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

TEST_BEGIN(MULPDv128v128_01, 1)
TEST_INPUTS(0)
    mulpd xmm0, xmm1
TEST_END

TEST_BEGIN(MULPDv128v128_45, 1)
TEST_INPUTS(0)
    mulpd xmm4, xmm5
TEST_END

#if APPLE_SAFE_TESTS

TEST_BEGIN(MULPDv128m128_01, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm1
    mulpd xmm0, [rsp - 16]
TEST_END

TEST_BEGIN(MULPDv128m128_45, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm5
    mulpd xmm4, [rsp - 16]
TEST_END

#endif

#if HAS_FEATURE_AVX
TEST_BEGIN(VMULPDv128v128_01, 1)
TEST_INPUTS(0)
    vmulpd xmm0, xmm0, xmm1
TEST_END

TEST_BEGIN(VMULPDv128v128_45, 1)
TEST_INPUTS(0)
    vmulpd xmm1, xmm4, xmm5
TEST_END

TEST_BEGIN(VMULPDv256v256_01, 1)
TEST_INPUTS(0)
    vmulpd ymm0, ymm0, ymm1
TEST_END

TEST_BEGIN(VMULPDv256v256_45, 1)
TEST_INPUTS(0)
    vmulpd ymm1, ymm4, ymm5
TEST_END

#if APPLE_SAFE_TESTS
TEST_BEGIN(VMULPDv128m128_45, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm5
    vmulpd xmm1, xmm4, [rsp - 16]
TEST_END

TEST_BEGIN(VMULPDv256m256_45, 1)
TEST_INPUTS(0)
    vmovdqu [rsp - 32], ymm5
    vmulpd ymm1, ymm4, [rsp - 32]
TEST_END
#endif  // APPLE_SAFE_TESTS
#endif
