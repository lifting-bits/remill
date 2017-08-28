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

TEST_BEGIN_64(MOVHPSv128m64, 1)
TEST_INPUTS(
    0)
    lea rsp, [rsp - 64]
    movhps xmm0,QWORD PTR [rsp - 0]  /* whatever is on the stack */
    movhps xmm1,QWORD PTR [rsp - 8]
    movhps xmm2,QWORD PTR [rsp - 16]
    movhps xmm3,QWORD PTR [rsp - 24]
    movhps xmm4,QWORD PTR [rsp - 32]
    movhps xmm5,QWORD PTR [rsp - 40]
    movhps xmm6,QWORD PTR [rsp - 48]
    movhps xmm7,QWORD PTR [rsp - 56]
TEST_END_64

TEST_BEGIN_64(MOVHPSm64v128, 1)
TEST_INPUTS(
    0)
    lea rsp, [rsp - 64]
    movhps QWORD PTR [rsp - 0], xmm0
    movhps QWORD PTR [rsp - 8], xmm1
    movhps QWORD PTR [rsp - 16], xmm2
    movhps QWORD PTR [rsp - 24], xmm3
    movhps QWORD PTR [rsp - 32], xmm4
    movhps QWORD PTR [rsp - 40], xmm5
    movhps QWORD PTR [rsp - 48], xmm6
    movhps QWORD PTR [rsp - 56], xmm7
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VMOVHPSvv128v128m64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 64]
    vmovhps xmm0, xmm1, QWORD PTR [rsp - 0]
    vmovhps xmm1, xmm2, QWORD PTR [rsp - 8]
    vmovhps xmm2, xmm3, QWORD PTR [rsp - 16]
    vmovhps xmm3, xmm4, QWORD PTR [rsp - 24]
    vmovhps xmm4, xmm5, QWORD PTR [rsp - 32]
    vmovhps xmm5, xmm6, QWORD PTR [rsp - 40]
    vmovhps xmm6, xmm7, QWORD PTR [rsp - 48]
TEST_END_64

TEST_BEGIN_64(VMOVHPSm64v128, 1)
TEST_INPUTS(
    0)
    lea rsp, [rsp - 64]
    vmovhps QWORD PTR [rsp - 0], xmm0
    vmovhps QWORD PTR [rsp - 8], xmm1
    vmovhps QWORD PTR [rsp - 16], xmm2
    vmovhps QWORD PTR [rsp - 24], xmm3
    vmovhps QWORD PTR [rsp - 32], xmm4
    vmovhps QWORD PTR [rsp - 40], xmm5
    vmovhps QWORD PTR [rsp - 48], xmm6
    vmovhps QWORD PTR [rsp - 56], xmm7
TEST_END_64

#endif  // HAS_FEATURE_AVX
