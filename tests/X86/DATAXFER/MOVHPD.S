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

TEST_BEGIN_64(MOVHPDv128m64, 1)
TEST_INPUTS(
    0)
    lea rsp, [rsp - 64]
    movhpd xmm0,QWORD PTR [rsp - 0]  /* whatever is on the stack */
    movhpd xmm1,QWORD PTR [rsp - 8]
    movhpd xmm2,QWORD PTR [rsp - 16]
    movhpd xmm3,QWORD PTR [rsp - 24]
    movhpd xmm4,QWORD PTR [rsp - 32]
    movhpd xmm5,QWORD PTR [rsp - 40]
    movhpd xmm6,QWORD PTR [rsp - 48]
    movhpd xmm7,QWORD PTR [rsp - 56]
TEST_END_64

TEST_BEGIN_64(MOVHPDm64v128, 1)
TEST_INPUTS(
    0)
    lea rsp, [rsp - 64]
    movhpd QWORD PTR [rsp - 0], xmm0
    movhpd QWORD PTR [rsp - 8], xmm1
    movhpd QWORD PTR [rsp - 16], xmm2
    movhpd QWORD PTR [rsp - 24], xmm3
    movhpd QWORD PTR [rsp - 32], xmm4
    movhpd QWORD PTR [rsp - 40], xmm5
    movhpd QWORD PTR [rsp - 48], xmm6
    movhpd QWORD PTR [rsp - 56], xmm7
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VMOVHPDvv128v128m64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 64]
    vmovhpd xmm0, xmm1, QWORD PTR [rsp - 0]
    vmovhpd xmm1, xmm2, QWORD PTR [rsp - 8]
    vmovhpd xmm2, xmm3, QWORD PTR [rsp - 16]
    vmovhpd xmm3, xmm4, QWORD PTR [rsp - 24]
    vmovhpd xmm4, xmm5, QWORD PTR [rsp - 32]
    vmovhpd xmm5, xmm6, QWORD PTR [rsp - 40]
    vmovhpd xmm6, xmm7, QWORD PTR [rsp - 48]
TEST_END_64

TEST_BEGIN_64(VMOVHPDm64v128, 1)
TEST_INPUTS(
    0)
    lea rsp, [rsp - 64]
    vmovhpd QWORD PTR [rsp - 0], xmm0
    vmovhpd QWORD PTR [rsp - 8], xmm1
    vmovhpd QWORD PTR [rsp - 16], xmm2
    vmovhpd QWORD PTR [rsp - 24], xmm3
    vmovhpd QWORD PTR [rsp - 32], xmm4
    vmovhpd QWORD PTR [rsp - 40], xmm5
    vmovhpd QWORD PTR [rsp - 48], xmm6
    vmovhpd QWORD PTR [rsp - 56], xmm7
TEST_END_64

#endif  // HAS_FEATURE_AVX
