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

TEST_BEGIN(CVTTSS2SIr32m32, 1)
TEST_INPUTS(
    0x7f7fffff,  // std::numeric_limits<float>::max()
    0x00800000,  // std::numeric_limits<float>::min()
    0x3f800000,  // +1.0
    0xbf800000,  // -1.0
    0x00000000,  // +0.0
    0x80000000,  // -0.0
    0x3f000000,  // +0.5
    0xbf000000,  // -0.5
    0x47c34fc0)  // 99999.5

    mov [rsp - 4], ARG1_32
    cvttss2si eax, [rsp - 4]
TEST_END

#endif  // APPLE_SAFE_TESTS

TEST_BEGIN(CVTTSS2SIr32v128, 1)
TEST_INPUTS(
    0x7f7fffff,  // std::numeric_limits<float>::max()
    0x00800000,  // std::numeric_limits<float>::min()
    0x3f800000,  // +1.0
    0xbf800000,  // -1.0
    0x00000000,  // +0.0
    0x80000000,  // -0.0
    0x3f000000,  // +0.5
    0xbf000000,  // -0.5
    0x47c34fc0)  // 99999.5

    movd xmm0, ARG1_32
    cvttss2si eax, xmm0
TEST_END

#if APPLE_SAFE_TESTS

TEST_BEGIN_64(CVTTSS2SIr64m32, 1)
TEST_INPUTS(
    0x7f7fffff,  // std::numeric_limits<float>::max()
    0x00800000,  // std::numeric_limits<float>::min()
    0x3f800000,  // +1.0
    0xbf800000,  // -1.0
    0x00000000,  // +0.0
    0x80000000,  // -0.0
    0x3f000000,  // +0.5
    0xbf000000,  // -0.5
    0x47c34fc0)  // 99999.5

    mov [rsp - 4], ARG1_32
    cvttss2si rax, [rsp - 4]
TEST_END_64

#endif  // APPLE_SAFE_TESTS

TEST_BEGIN_64(CVTTSS2SIr64v128, 1)
TEST_INPUTS(
    0x7f7fffff,  // std::numeric_limits<float>::max()
    0x00800000,  // std::numeric_limits<float>::min()
    0x3f800000,  // +1.0
    0xbf800000,  // -1.0
    0x00000000,  // +0.0
    0x80000000,  // -0.0
    0x3f000000,  // +0.5
    0xbf000000,  // -0.5
    0x47c34fc0)  // 99999.5

    movd xmm0, ARG1_32
    cvttss2si rax, xmm0
TEST_END_64

#if HAS_FEATURE_AVX

#if APPLE_SAFE_TESTS

TEST_BEGIN(VCVTTSS2SIr32m32, 1)
TEST_INPUTS(
    0x7f7fffff,  // std::numeric_limits<float>::max()
    0x00800000,  // std::numeric_limits<float>::min()
    0x3f800000,  // +1.0
    0xbf800000,  // -1.0
    0x00000000,  // +0.0
    0x80000000,  // -0.0
    0x3f000000,  // +0.5
    0xbf000000,  // -0.5
    0x47c34fc0)  // 99999.5

    mov [rsp - 4], ARG1_32
    vcvttss2si eax, DWORD PTR [rsp - 4]
TEST_END

#endif  // APPLE_SAFE_TESTS

TEST_BEGIN(VCVTTSS2SIr32v128, 1)
TEST_INPUTS(
    0x7f7fffff,  // std::numeric_limits<float>::max()
    0x00800000,  // std::numeric_limits<float>::min()
    0x3f800000,  // +1.0
    0xbf800000,  // -1.0
    0x00000000,  // +0.0
    0x80000000,  // -0.0
    0x3f000000,  // +0.5
    0xbf000000,  // -0.5
    0x47c34fc0)  // 99999.5

    movd xmm0, ARG1_32
    vcvttss2si eax, xmm0
TEST_END

#if APPLE_SAFE_TESTS

TEST_BEGIN_64(VCVTTSS2SIr64m32, 1)
TEST_INPUTS(
    0x7f7fffff,  // std::numeric_limits<float>::max()
    0x00800000,  // std::numeric_limits<float>::min()
    0x3f800000,  // +1.0
    0xbf800000,  // -1.0
    0x00000000,  // +0.0
    0x80000000,  // -0.0
    0x3f000000,  // +0.5
    0xbf000000,  // -0.5
    0x47c34fc0)  // 99999.5

    mov [rsp - 4], ARG1_32
    vcvttss2si rax, DWORD PTR [rsp - 4]
TEST_END_64

#endif  // APPLE_SAFE_TESTS

TEST_BEGIN_64(VCVTTSS2SIr64v128, 1)
TEST_INPUTS(
    0x7f7fffff,  // std::numeric_limits<float>::max()
    0x00800000,  // std::numeric_limits<float>::min()
    0x3f800000,  // +1.0
    0xbf800000,  // -1.0
    0x00000000,  // +0.0
    0x80000000,  // -0.0
    0x3f000000,  // +0.5
    0xbf000000,  // -0.5
    0x47c34fc0)  // 99999.5

    movd xmm0, ARG1_32
    vcvttss2si rax, xmm0
TEST_END_64

#endif  // HAS_FEATURE_AVX
