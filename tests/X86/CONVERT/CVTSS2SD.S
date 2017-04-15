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

TEST_BEGIN_64(CVTSS2SDv128m32, 1)
TEST_INPUTS(
    0x3fffffff,
    0x40000000,
    0x7FFFFFFF,
    0x80000000)

    push ARG1_64
    cvtss2sd xmm0, DWORD PTR [rsp]
TEST_END_64

TEST_BEGIN(CVTSS2SDv128v128, 1)
TEST_INPUTS(0)
    cvtss2sd xmm0, xmm1
    cvtss2sd xmm1, xmm2
    cvtss2sd xmm2, xmm3
    cvtss2sd xmm3, xmm4
TEST_END

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VCVTSS2SDv128v128m64, 1)
TEST_INPUTS(
    0x3fffffff,
    0x40000000,
    0x7FFFFFFF,
    0x80000000)

    push ARG1_64
    vcvtss2sd xmm0, xmm1, DWORD PTR [rsp]
TEST_END_64

TEST_BEGIN(VCVTSS2SDv128v128v128, 1)
TEST_INPUTS(0)
    vcvtss2sd xmm0, xmm1, xmm2
    vcvtss2sd xmm1, xmm2, xmm3
    vcvtss2sd xmm2, xmm3, xmm4
    vcvtss2sd xmm3, xmm4, xmm5
TEST_END

#endif  // HAS_FEATURE_AVX
