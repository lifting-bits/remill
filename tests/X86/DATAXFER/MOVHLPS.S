
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

TEST_BEGIN_64(MOVHLPSv128v128, 1)
TEST_INPUTS(0)
    movhlps xmm0, xmm1
    movhlps xmm1, xmm2
    movhlps xmm3, xmm4
    movhlps xmm4, xmm0
    movhlps xmm0, xmm0
TEST_END_64

#if HAS_FEATURE_AVX
TEST_BEGIN_64(VMOVHLPSvv128v128v128, 1)
TEST_INPUTS(0)
    vmovhlps xmm0, xmm1, xmm2
    vmovhlps xmm1, xmm2, xmm3
    vmovhlps xmm2, xmm3, xmm4
    vmovhlps xmm4, xmm0, xmm1
    vmovhlps xmm0, xmm1, xmm1
    vmovhlps xmm0, xmm0, xmm0
TEST_END_64
#endif  // HAS_FEATURE_AVX
