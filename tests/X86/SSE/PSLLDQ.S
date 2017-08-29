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

TEST_BEGIN(PSLLDQv128v128i8, 1)
TEST_INPUTS(
    0)
    pslldq xmm0, 0
    pslldq xmm1, 1
    pslldq xmm2, 2
    pslldq xmm3, 3
    pslldq xmm4, 4
    pslldq xmm5, 14
    pslldq xmm6, 15
    pslldq xmm7, 16
TEST_END

#if HAS_FEATURE_AVX

TEST_BEGIN(VPSLLDQv128v128i8, 1)
TEST_INPUTS(
    0)
    vpslldq xmm1, xmm0, 1
    vpslldq xmm2, xmm0, 2
    vpslldq xmm3, xmm0, 3
    vpslldq xmm4, xmm0, 4
    vpslldq xmm5, xmm0, 14
    vpslldq xmm6, xmm0, 15
    vpslldq xmm7, xmm0, 16
TEST_END

TEST_BEGIN(VPSLLDQv256v256i8, 1)
TEST_INPUTS(
    0)
    vpslldq ymm1, ymm0, 1
    vpslldq ymm2, ymm0, 2
    vpslldq ymm3, ymm0, 3
    vpslldq ymm4, ymm0, 4
    vpslldq ymm5, ymm0, 14
    vpslldq ymm6, ymm0, 15
    vpslldq ymm7, ymm0, 16
TEST_END

#endif  // HAS_FEATURE_AVX
