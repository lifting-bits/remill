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

TEST_BEGIN(ADDSSv128v128_04, 1)
TEST_INPUTS(0)
    addss xmm0, xmm4
TEST_END

TEST_BEGIN(ADDSSv128v128_40, 1)
TEST_INPUTS(0)
    addss xmm4, xmm0
TEST_END

#if APPLE_SAFE_TESTS

TEST_BEGIN(ADDSSv128m128_04, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm4
    addss xmm0, [rsp - 16]
TEST_END

TEST_BEGIN(ADDSSv128m128_40, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm0
    addss xmm4, [rsp - 16]
TEST_END

#endif  // APPLE_SAFE_TESTS

#if HAS_FEATURE_AVX
TEST_BEGIN(VADDSSv128v128_04, 1)
TEST_INPUTS(0)
    vaddss xmm0, xmm1, xmm4
TEST_END

TEST_BEGIN(VADDSSv128v128_40, 1)
TEST_INPUTS(0)
    vaddss xmm1, xmm4, xmm0
TEST_END

#if APPLE_SAFE_TESTS
TEST_BEGIN_64(VADDSSv128m32_40, 1)
TEST_INPUTS(
    0x3f800000,
    0x40490fdb,
    0x47c34f80)

    mov DWORD PTR [rsp - 16], ARG1_32
    vaddss xmm1, xmm4, DWORD PTR [rsp - 16]
TEST_END_64
#endif  // APPLE_SAFE_TESTS
#endif  // HAS_FEATURE_AVX
