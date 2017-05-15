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

TEST_BEGIN_64(COMISDv128v128, 2)
TEST_INPUTS(
    0x3ff0000000000000 /* 1.000000 */, 0x3ff0000000000000, /* 1.000000 */
    0x3ff0000000000000 /* 1.000000 */, 0x4000000000000000, /* 2.000000 */
    0x4000000000000000 /* 2.000000 */, 0x3ff0000000000000, /* 1.000000 */
    0x3ff0000000000000 /* 1.000000 */, 0x7ff0000000000000, /* inf */
    0x7ff0000000000000 /* inf */, 0x3ff0000000000000, /* 1.000000 */
    0x3ff0000000000000 /* 1.000000 */, 0xfff0000000000000, /* -inf */
    0xfff0000000000000 /* -inf */, 0x3ff0000000000000, /* 1.000000 */
    0x7ff0000000000000 /* inf */, 0x7ff0000000000000, /* inf */
    0xfff0000000000000 /* -inf */, 0xfff0000000000000, /* -inf */
    0x3ff0000000000000 /* 1.000000 */, 0x7ff8000000000000, /* nan */
    0x7ff8000000000000 /* nan */, 0x3ff0000000000000, /* 1.000000 */
    0x7ff8000000000000 /* nan */, 0x7ff8000000000000, /* nan */
    0x7ff0000000000000 /* inf */, 0x7ff8000000000000, /* nan */
    0x7ff8000000000000 /* nan */, 0x7ff0000000000000 /* inf */ )
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    comisd xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(COMISDv128m64, 2)
TEST_INPUTS(
    0x3ff0000000000000 /* 1.000000 */, 0x3ff0000000000000, /* 1.000000 */
    0x3ff0000000000000 /* 1.000000 */, 0x4000000000000000, /* 2.000000 */
    0x4000000000000000 /* 2.000000 */, 0x3ff0000000000000, /* 1.000000 */
    0x3ff0000000000000 /* 1.000000 */, 0x7ff0000000000000, /* inf */
    0x7ff0000000000000 /* inf */, 0x3ff0000000000000, /* 1.000000 */
    0x3ff0000000000000 /* 1.000000 */, 0xfff0000000000000, /* -inf */
    0xfff0000000000000 /* -inf */, 0x3ff0000000000000, /* 1.000000 */
    0x7ff0000000000000 /* inf */, 0x7ff0000000000000, /* inf */
    0xfff0000000000000 /* -inf */, 0xfff0000000000000, /* -inf */
    0x3ff0000000000000 /* 1.000000 */, 0x7ff8000000000000, /* nan */
    0x7ff8000000000000 /* nan */, 0x3ff0000000000000, /* 1.000000 */
    0x7ff8000000000000 /* nan */, 0x7ff8000000000000, /* nan */
    0x7ff0000000000000 /* inf */, 0x7ff8000000000000, /* nan */
    0x7ff8000000000000 /* nan */, 0x7ff0000000000000 /* inf */ )
    push ARG2_64
    movq xmm0, ARG1_64
    // comisd xmm0, qword ptr [rsp]
    .byte 0x66, 0x0f, 0x2f, 0x04, 0x24
TEST_END_64

#if HAS_FEATURE_AVX
TEST_BEGIN_64(VCOMISDv128v128, 2)
TEST_INPUTS(
    0x3ff0000000000000 /* 1.000000 */, 0x3ff0000000000000, /* 1.000000 */
    0x3ff0000000000000 /* 1.000000 */, 0x4000000000000000, /* 2.000000 */
    0x4000000000000000 /* 2.000000 */, 0x3ff0000000000000, /* 1.000000 */
    0x3ff0000000000000 /* 1.000000 */, 0x7ff0000000000000, /* inf */
    0x7ff0000000000000 /* inf */, 0x3ff0000000000000, /* 1.000000 */
    0x3ff0000000000000 /* 1.000000 */, 0xfff0000000000000, /* -inf */
    0xfff0000000000000 /* -inf */, 0x3ff0000000000000, /* 1.000000 */
    0x7ff0000000000000 /* inf */, 0x7ff0000000000000, /* inf */
    0xfff0000000000000 /* -inf */, 0xfff0000000000000, /* -inf */
    0x3ff0000000000000 /* 1.000000 */, 0x7ff8000000000000, /* nan */
    0x7ff8000000000000 /* nan */, 0x3ff0000000000000, /* 1.000000 */
    0x7ff8000000000000 /* nan */, 0x7ff8000000000000, /* nan */
    0x7ff0000000000000 /* inf */, 0x7ff8000000000000, /* nan */
    0x7ff8000000000000 /* nan */, 0x7ff0000000000000 /* inf */ )
    vmovq xmm0, ARG1_64
    vmovq xmm1, ARG2_64
    vcomisd xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(VCOMISDv128m64, 2)
TEST_INPUTS(
    0x3ff0000000000000 /* 1.000000 */, 0x3ff0000000000000, /* 1.000000 */
    0x3ff0000000000000 /* 1.000000 */, 0x4000000000000000, /* 2.000000 */
    0x4000000000000000 /* 2.000000 */, 0x3ff0000000000000, /* 1.000000 */
    0x3ff0000000000000 /* 1.000000 */, 0x7ff0000000000000, /* inf */
    0x7ff0000000000000 /* inf */, 0x3ff0000000000000, /* 1.000000 */
    0x3ff0000000000000 /* 1.000000 */, 0xfff0000000000000, /* -inf */
    0xfff0000000000000 /* -inf */, 0x3ff0000000000000, /* 1.000000 */
    0x7ff0000000000000 /* inf */, 0x7ff0000000000000, /* inf */
    0xfff0000000000000 /* -inf */, 0xfff0000000000000, /* -inf */
    0x3ff0000000000000 /* 1.000000 */, 0x7ff8000000000000, /* nan */
    0x7ff8000000000000 /* nan */, 0x3ff0000000000000, /* 1.000000 */
    0x7ff8000000000000 /* nan */, 0x7ff8000000000000, /* nan */
    0x7ff0000000000000 /* inf */, 0x7ff8000000000000, /* nan */
    0x7ff8000000000000 /* nan */, 0x7ff0000000000000 /* inf */ )
    push ARG2_64
    vmovq xmm0, ARG1_64

    //vcomisd xmm0, qword ptr [rsp]
    .byte 0xc5, 0xf9, 0x2f, 0x04, 0x24
TEST_END_64
#endif  // HAS_FEATURE_AVX
