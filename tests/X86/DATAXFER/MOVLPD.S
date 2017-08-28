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

TEST_BEGIN_64(MOVLPDv128m64, 1)
TEST_INPUTS(
    0)
    lea rsp, [rsp - 64]
    movlpd xmm0,QWORD PTR [rsp - 0]  /* whatever is on the stack */
    movlpd xmm1,QWORD PTR [rsp - 8]
    movlpd xmm2,QWORD PTR [rsp - 16]
    movlpd xmm3,QWORD PTR [rsp - 24]
    movlpd xmm4,QWORD PTR [rsp - 32]
    movlpd xmm5,QWORD PTR [rsp - 40]
    movlpd xmm6,QWORD PTR [rsp - 48]
    movlpd xmm7,QWORD PTR [rsp - 56]
TEST_END_64

TEST_BEGIN_64(MOVLPDm64v128, 1)
TEST_INPUTS(
    0)
    lea rsp, [rsp - 64]
    movlpd QWORD PTR [rsp - 0], xmm0
    movlpd QWORD PTR [rsp - 8], xmm1
    movlpd QWORD PTR [rsp - 16], xmm2
    movlpd QWORD PTR [rsp - 24], xmm3
    movlpd QWORD PTR [rsp - 32], xmm4
    movlpd QWORD PTR [rsp - 40], xmm5
    movlpd QWORD PTR [rsp - 48], xmm6
    movlpd QWORD PTR [rsp - 56], xmm7
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VMOVLPDvv128v128m64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 64]
    vmovlpd xmm0, xmm1, QWORD PTR [rsp - 0]
    vmovlpd xmm1, xmm2, QWORD PTR [rsp - 8]
    vmovlpd xmm2, xmm3, QWORD PTR [rsp - 16]
    vmovlpd xmm3, xmm4, QWORD PTR [rsp - 24]
    vmovlpd xmm4, xmm5, QWORD PTR [rsp - 32]
    vmovlpd xmm5, xmm6, QWORD PTR [rsp - 40]
    vmovlpd xmm6, xmm7, QWORD PTR [rsp - 48]
TEST_END_64

TEST_BEGIN_64(VMOVLPDm64v128, 1)
TEST_INPUTS(
    0)
    lea rsp, [rsp - 64]
    vmovlpd QWORD PTR [rsp - 0], xmm0
    vmovlpd QWORD PTR [rsp - 8], xmm1
    vmovlpd QWORD PTR [rsp - 16], xmm2
    vmovlpd QWORD PTR [rsp - 24], xmm3
    vmovlpd QWORD PTR [rsp - 32], xmm4
    vmovlpd QWORD PTR [rsp - 40], xmm5
    vmovlpd QWORD PTR [rsp - 48], xmm6
    vmovlpd QWORD PTR [rsp - 56], xmm7
TEST_END_64

#endif  // HAS_FEATURE_AVX
