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

TEST_BEGIN(ADDSDv128v128_04, 1)
TEST_INPUTS(0)
    addsd xmm0, xmm4
TEST_END

TEST_BEGIN(ADDSDv128v128_40, 1)
TEST_INPUTS(0)
    addsd xmm4, xmm0
TEST_END

#if APPLE_SAFE_TESTS

TEST_BEGIN(ADDSDv128m128_04, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm4
    addsd xmm0, [rsp - 16]
TEST_END

TEST_BEGIN(ADDSDv128m128_40, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm0
    addsd xmm4, [rsp - 16]
TEST_END

#endif  // APPLE_SAFE_TESTS

#if HAS_FEATURE_AVX

TEST_BEGIN(VADDSDv128v128_04, 1)
TEST_INPUTS(0)
    vaddsd xmm0, xmm1, xmm4
TEST_END

TEST_BEGIN(VADDSDv128v128_40, 1)
TEST_INPUTS(0)
    vaddsd xmm1, xmm4, xmm0
TEST_END

#if APPLE_SAFE_TESTS
TEST_BEGIN_64(VADDSDv128m32_40, 1)
TEST_INPUTS(
    0x3ff0000000000000,
    0x400921fb54442d18,
    0x40f869f000000000)

    mov QWORD PTR [rsp - 16], ARG1_64
    vaddsd xmm1, xmm4, QWORD PTR [rsp - 16]
TEST_END_64
#endif  // APPLE_SAFE_TESTS

#endif  // HAS_FEATURE_AVX
