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

TEST_BEGIN_64(COMISSv128v128, 2)
TEST_INPUTS(
    0x3f800000 /* 1.000000 */, 0x3f800000, /* 1.000000 */
    0x3f800000 /* 1.000000 */, 0x40000000, /* 2.000000 */
    0x40000000 /* 2.000000 */, 0x3f800000, /* 1.000000 */
    0x3f800000 /* 1.000000 */, 0x7f800000, /* inf */
    0x7f800000 /* inf */, 0x3f800000, /* 1.000000 */
    0x3f800000 /* 1.000000 */, 0xff800000, /* -inf */
    0xff800000 /* -inf */, 0x3f800000, /* 1.000000 */
    0x7f800000 /* inf */, 0x7f800000, /* inf */
    0xff800000 /* -inf */, 0xff800000, /* -inf */
    0x3f800000 /* 1.000000 */, 0x7fc00000, /* nan */
    0x7fc00000 /* nan */, 0x3f800000, /* 1.000000 */
    0x7fc00000 /* nan */, 0x7fc00000, /* nan */
    0x7f800000 /* inf */, 0x7fc00000, /* nan */
    0x7fc00000 /* nan */, 0x7f800000 /* inf */ )
    movd xmm0, ARG1_32
    movd xmm1, ARG2_32
    comiss xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(COMISSv128m32, 2)
TEST_INPUTS(
    0x3f800000 /* 1.000000 */, 0x3f800000, /* 1.000000 */
    0x3f800000 /* 1.000000 */, 0x40000000, /* 2.000000 */
    0x40000000 /* 2.000000 */, 0x3f800000, /* 1.000000 */
    0x3f800000 /* 1.000000 */, 0x7f800000, /* inf */
    0x7f800000 /* inf */, 0x3f800000, /* 1.000000 */
    0x3f800000 /* 1.000000 */, 0xff800000, /* -inf */
    0xff800000 /* -inf */, 0x3f800000, /* 1.000000 */
    0x7f800000 /* inf */, 0x7f800000, /* inf */
    0xff800000 /* -inf */, 0xff800000, /* -inf */
    0x3f800000 /* 1.000000 */, 0x7fc00000, /* nan */
    0x7fc00000 /* nan */, 0x3f800000, /* 1.000000 */
    0x7fc00000 /* nan */, 0x7fc00000, /* nan */
    0x7f800000 /* inf */, 0x7fc00000, /* nan */
    0x7fc00000 /* nan */, 0x7f800000 /* inf */ )
    push ARG2_64
    movd xmm0, ARG1_32
    //comiss xmm0, dword ptr [rsp]
    .byte 0x0f, 0x2f, 0x04, 0x24
TEST_END_64

#if HAS_FEATURE_AVX
TEST_BEGIN_64(VCOMISSv128v128, 2)
TEST_INPUTS(
    0x3f800000 /* 1.000000 */, 0x3f800000, /* 1.000000 */
    0x3f800000 /* 1.000000 */, 0x40000000, /* 2.000000 */
    0x40000000 /* 2.000000 */, 0x3f800000, /* 1.000000 */
    0x3f800000 /* 1.000000 */, 0x7f800000, /* inf */
    0x7f800000 /* inf */, 0x3f800000, /* 1.000000 */
    0x3f800000 /* 1.000000 */, 0xff800000, /* -inf */
    0xff800000 /* -inf */, 0x3f800000, /* 1.000000 */
    0x7f800000 /* inf */, 0x7f800000, /* inf */
    0xff800000 /* -inf */, 0xff800000, /* -inf */
    0x3f800000 /* 1.000000 */, 0x7fc00000, /* nan */
    0x7fc00000 /* nan */, 0x3f800000, /* 1.000000 */
    0x7fc00000 /* nan */, 0x7fc00000, /* nan */
    0x7f800000 /* inf */, 0x7fc00000, /* nan */
    0x7fc00000 /* nan */, 0x7f800000 /* inf */ )
    vmovd xmm0, ARG1_32
    vmovd xmm1, ARG2_32
    vcomiss xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(VCOMISSv128m32, 2)
TEST_INPUTS(
    0x3f800000 /* 1.000000 */, 0x3f800000, /* 1.000000 */
    0x3f800000 /* 1.000000 */, 0x40000000, /* 2.000000 */
    0x40000000 /* 2.000000 */, 0x3f800000, /* 1.000000 */
    0x3f800000 /* 1.000000 */, 0x7f800000, /* inf */
    0x7f800000 /* inf */, 0x3f800000, /* 1.000000 */
    0x3f800000 /* 1.000000 */, 0xff800000, /* -inf */
    0xff800000 /* -inf */, 0x3f800000, /* 1.000000 */
    0x7f800000 /* inf */, 0x7f800000, /* inf */
    0xff800000 /* -inf */, 0xff800000, /* -inf */
    0x3f800000 /* 1.000000 */, 0x7fc00000, /* nan */
    0x7fc00000 /* nan */, 0x3f800000, /* 1.000000 */
    0x7fc00000 /* nan */, 0x7fc00000, /* nan */
    0x7f800000 /* inf */, 0x7fc00000, /* nan */
    0x7fc00000 /* nan */, 0x7f800000 /* inf */ )
    push ARG2_64
    vmovd xmm0, ARG1_32
    // vcomiss xmm0, dword ptr [rsp]
    .byte 0xc5, 0xf8, 0x2f, 0x04, 0x24
TEST_END_64
#endif  // HAS_FEATURE_AVX
