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

TEST_BEGIN(MULSSv128v128_01, 1)
TEST_INPUTS(0)
    mulss xmm0, xmm1
TEST_END

TEST_BEGIN(MULSSv128v128_45, 1)
TEST_INPUTS(0)
    mulss xmm4, xmm5
TEST_END

#if APPLE_SAFE_TESTS

TEST_BEGIN(MULSSv128m128_01, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm1
    mulss xmm0, [rsp - 16]
TEST_END

TEST_BEGIN(MULSSv128m128_45, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm5
    mulss xmm4, [rsp - 16]
TEST_END

#endif  // APPLE_SAFE_TESTS

#if HAS_FEATURE_AVX
TEST_BEGIN(VMULSSv128v128_01, 1)
TEST_INPUTS(0)
    vmulss xmm0, xmm0, xmm1
TEST_END

TEST_BEGIN(VMULSSv128v128_45, 1)
TEST_INPUTS(0)
    vmulss xmm1, xmm4, xmm5
TEST_END

#if APPLE_SAFE_TESTS
TEST_BEGIN_64(VMULSSv128m32_45, 1)
TEST_INPUTS(
    0x3f800000,
    0x40490fdb,
    0x47c34f80)

    mov DWORD PTR [rsp - 16], ARG1_32
    vmulss xmm1, xmm4, DWORD PTR [rsp - 16]
TEST_END_64
#endif  // APPLE_SAFE_TESTS
#endif  // HAS_FEATURE_AVX
