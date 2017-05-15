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

TEST_BEGIN(MOVDv128r32, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0xFFFF,
    0xFFFFFFFF)

    movd xmm0, ARG1_32
TEST_END

TEST_BEGIN(MOVDr32v128, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0xFFFF,
    0xFFFFFFFF)

    movd xmm0, ARG1_32
    movd ARG2_32, xmm0
TEST_END

#if APPLE_SAFE_TESTS
TEST_BEGIN(MOVDv128m32, 1)
TEST_INPUTS(
    0)
    movd xmm0, DWORD PTR [rsp - 16]  // Same encoding in 32-bit.
TEST_END

TEST_BEGIN(MOVDv128m32_4, 1)
TEST_INPUTS(
    0)
    movd xmm4, DWORD PTR [rsp - 16]  // Same encoding in 32-bit.
TEST_END

TEST_BEGIN(MOVDm32v128, 1)
TEST_INPUTS(
    0)
    movd DWORD PTR [rsp - 16], xmm0  // Same encoding in 32-bit.
TEST_END
#endif  // APPLE_SAFE_TESTS

#if HAS_FEATURE_AVX
TEST_BEGIN(VMOVDv128r32, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0xFFFF,
    0xFFFFFFFF)

    vmovd xmm0, ARG1_32
TEST_END

TEST_BEGIN(VMOVDr32v128, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0xFFFF,
    0xFFFFFFFF)

    vmovd xmm0, ARG1_32
    vmovd ARG2_32, xmm0
TEST_END

#if APPLE_SAFE_TESTS
TEST_BEGIN(VMOVDv128m32, 1)
TEST_INPUTS(
    0)
    vmovd xmm0, DWORD PTR [rsp - 16]  // Same encoding in 32-bit.
TEST_END

TEST_BEGIN(VMOVDv128m32_4, 1)
TEST_INPUTS(
    0)
    vmovd xmm4, DWORD PTR [rsp - 16]  // Same encoding in 32-bit.
TEST_END

TEST_BEGIN(VMOVDm32v128, 1)
TEST_INPUTS(
    0)
    vmovd DWORD PTR [rsp - 16], xmm0  // Same encoding in 32-bit.
TEST_END
#endif  // APPLE_SAFE_TESTS
#endif  // HAS_FEATURE_AVX

TEST_BEGIN(MOVDmm64r32, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0xFFFF,
    0xFFFFFFFF)

    movd mm0, ARG1_32
TEST_END

#if APPLE_SAFE_TESTS

TEST_BEGIN_64(MOVDmm64m32, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0xFFFF,
    0xFFFFFFFF)

    push ARG1_64
    movd mm0, DWORD PTR [rsp]
TEST_END_64

TEST_BEGIN(MOVDm64mm64, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0xFFFF,
    0xFFFFFFFF)

    movd mm0, ARG1_32
    movd [rsp - 16], mm0
TEST_END

#endif  // APPLE_SAFE_TESTS
