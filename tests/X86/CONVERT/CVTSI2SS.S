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

TEST_BEGIN(CVTSI2SSv128r32, 1)
TEST_INPUTS(
    0,
    1,
    0xffffffff,
    0x7fffffff,
    0x80000000)

    cvtsi2ss xmm0, ARG1_32
TEST_END

TEST_BEGIN_64(CVTSI2SSv128r64, 1)
TEST_INPUTS(
    0,
    1,
    0xffffffff,
    0x7fffffff,
    0x80000000,
    0xffffffffffffffff,
    0x7fffffffffffffff,
    0x8000000000000000)

    cvtsi2ss xmm0, ARG1_64
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN(VCVTSI2SSv128v128r32, 1)
TEST_INPUTS(
    0,
    1,
    0xffffffff,
    0x7fffffff,
    0x80000000)

    vcvtsi2ss xmm0, xmm1, ARG1_32
TEST_END

TEST_BEGIN_64(VCVTSI2SSv128v128r64, 1)
TEST_INPUTS(
    0,
    1,
    0xffffffff,
    0x7fffffff,
    0x80000000,
    0xffffffffffffffff,
    0x7fffffffffffffff,
    0x8000000000000000)

    vcvtsi2ss xmm0, xmm1, ARG1_64
TEST_END_64

#endif  // HAS_FEATURE_AVX
