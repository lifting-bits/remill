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

#if HAS_FEATURE_AVX

// TODO: define a good list of floating point corner case values

TEST_BEGIN_64(VFMSUB132SDv128v128m64, 1)
TEST_INPUTS(0)
    push 0x0000000001234567;
    vfmsub132sd xmm0, xmm1, qword ptr [rsp];
TEST_END_64

TEST_BEGIN_64(VFMSUB132SDv128v128v128, 1)
TEST_INPUTS(0)
    vfmsub132sd xmm0, xmm1, xmm2;
TEST_END_64

TEST_BEGIN_64(VFMSUB213SDv128v128m64, 1)
TEST_INPUTS(0)
    push 0x0000000001234567;
    vfmsub213sd xmm0, xmm1, qword ptr [rsp];
TEST_END_64

TEST_BEGIN_64(VFMSUB213SDv128v128v128, 1)
TEST_INPUTS(0)
    vfmsub213sd xmm0, xmm1, xmm2;
TEST_END_64

TEST_BEGIN_64(VFMSUB231SDv128v128m64, 1)
TEST_INPUTS(0xfedcba9876543210)
    push ARG1_64;
    vfmsub231sd xmm0, xmm1, qword ptr [rsp];
TEST_END_64

TEST_BEGIN_64(VFMSUB231SDv128v128v128, 3)
TEST_INPUTS(0.0, 0.0, 0.0,
            1.0, 1.0, 1.0,
            1.2, 2.3, 3.4)
    movq xmm0, ARG1_64;
    movq xmm1, ARG2_64;
    movq xmm2, ARG3_64;
    vfmsub231sd xmm0, xmm1, xmm2;
TEST_END_64

#endif  // HAS_FEATURE_AVX