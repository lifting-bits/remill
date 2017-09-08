
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

TEST_BEGIN_64(MOVLHPSv128v128, 2)
TEST_INPUTS(
    0x0000000000000000, 0x0000000000000000,  // sanity check
    0xaaaaaaaaaaaaaaaa, 0x0000000000000000,  // arbitrarily chosen values
    0xdeadbeefdeadbeef, 0xfacefeedfacefeed,  // other arbitrarily chosen values
    0x00000000deadbeef, 0x00000000facefeed)
    movq xmm0, ARG1_64;   // load the low QWORD of v128 dest
    movq xmm1, ARG2_64;   // load the low QWORD of v128 src
    movlhps xmm0, xmm1
TEST_END_64

#if HAS_FEATURE_AVX
TEST_BEGIN_64(VMOVLHPSvv128v128v128, 2)
TEST_INPUTS(
    0x0000000000000000, 0x0000000000000000,  // sanity check
    0xaaaaaaaaaaaaaaaa, 0x0000000000000000,  // arbitrarily chosen values
    0xdeadbeefdeadbeef, 0xfacefeedfacefeed,
    0x00000000deadbeef, 0x00000000facefeed)  // other arbitrarily chosen values
    movq xmm1, ARG1_64
    movq xmm2, ARG2_64
    vmovlhps xmm0, xmm1, xmm2
TEST_END_64
#endif  // HAS_FEATURE_AVX
