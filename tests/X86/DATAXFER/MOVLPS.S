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

TEST_BEGIN_64(MOVLPSv128m64, 1)
TEST_INPUTS(
    0)
    lea rsp, [rsp - 64]
    movlps xmm0,QWORD PTR [rsp - 0]  /* whatever is on the stack */
    movlps xmm1,QWORD PTR [rsp - 8]
    movlps xmm2,QWORD PTR [rsp - 16]
    movlps xmm3,QWORD PTR [rsp - 24]
    movlps xmm4,QWORD PTR [rsp - 32]
    movlps xmm5,QWORD PTR [rsp - 40]
    movlps xmm6,QWORD PTR [rsp - 48]
    movlps xmm7,QWORD PTR [rsp - 56]
TEST_END_64

TEST_BEGIN_64(MOVLPSm64v128, 1)
TEST_INPUTS(
    0)
    lea rsp, [rsp - 64]
    movlps QWORD PTR [rsp - 0], xmm0
    movlps QWORD PTR [rsp - 8], xmm1
    movlps QWORD PTR [rsp - 16], xmm2
    movlps QWORD PTR [rsp - 24], xmm3
    movlps QWORD PTR [rsp - 32], xmm4
    movlps QWORD PTR [rsp - 40], xmm5
    movlps QWORD PTR [rsp - 48], xmm6
    movlps QWORD PTR [rsp - 56], xmm7
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VMOVLPSvv128v128m64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 64]
    vmovlps xmm0, xmm1, QWORD PTR [rsp - 0]
    vmovlps xmm1, xmm2, QWORD PTR [rsp - 8]
    vmovlps xmm2, xmm3, QWORD PTR [rsp - 16]
    vmovlps xmm3, xmm4, QWORD PTR [rsp - 24]
    vmovlps xmm4, xmm5, QWORD PTR [rsp - 32]
    vmovlps xmm5, xmm6, QWORD PTR [rsp - 40]
    vmovlps xmm6, xmm7, QWORD PTR [rsp - 48]
TEST_END_64

TEST_BEGIN_64(VMOVLPSm64v128, 1)
TEST_INPUTS(
    0)
    lea rsp, [rsp - 64]
    vmovlps QWORD PTR [rsp - 0], xmm0
    vmovlps QWORD PTR [rsp - 8], xmm1
    vmovlps QWORD PTR [rsp - 16], xmm2
    vmovlps QWORD PTR [rsp - 24], xmm3
    vmovlps QWORD PTR [rsp - 32], xmm4
    vmovlps QWORD PTR [rsp - 40], xmm5
    vmovlps QWORD PTR [rsp - 48], xmm6
    vmovlps QWORD PTR [rsp - 56], xmm7
TEST_END_64

#endif  // HAS_FEATURE_AVX
