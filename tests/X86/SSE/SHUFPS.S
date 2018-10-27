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

#define SHUFPS_INPUTS_64 \
    0xF82DAC26, 0x091D41A7, \
    0x5FD4D3D9, 0x39A5f1D8, \
    0x063F0DDF, 0xAA9352B2, \
    0xD4A19DBB, 0x2D81A606, \
    0xBD2A7045, 0x8FC05637, \
    0x75D9B52A, 0x0AA1300B, \
    0x55535FB8, 0x4952FFC7, \
    0x06EA7DD6, 0x2D6EDF79, \
    0x49974EBE, 0xD64D34E8, \
    0x21E9840E, 0x6B56224B, \
    0x5B3631FD, 0xA03337FF, \
    0xEE92c9F3, 0x3B786526

TEST_BEGIN_64(SHUFPSv128v128imm8_6d, 2)
TEST_INPUTS(SHUFPS_INPUTS_64)
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    shufps xmm0, xmm1, 0x6d
TEST_END_64

TEST_BEGIN_64(SHUFPSv128v128imm8_b1, 2)
TEST_INPUTS(SHUFPS_INPUTS_64)
    push ARG1_64
    push ARG1_64
    movq xmm0, [rsp]
    push ARG2_64
    push ARG2_64
    movq xmm1, [rsp]
    shufps xmm0, xmm1, 0xb1
TEST_END_64

TEST_BEGIN_64(SHUFPSv128v128imm8_96, 2)
TEST_INPUTS(SHUFPS_INPUTS_64)
    movq xmm1, ARG1_64
    movq xmm2, ARG2_64
    shufps xmm1, xmm2, 0x96
TEST_END_64

TEST_BEGIN_64(SHUFPSv128v128imm8_8c, 2)
TEST_INPUTS(SHUFPS_INPUTS_64)
    movq xmm4, ARG1_64
    movq xmm3, ARG2_64
    shufps xmm4, xmm3, 0x8c
TEST_END_64

TEST_BEGIN_64(SHUFPSv128v128imm8_73, 2)
TEST_INPUTS(SHUFPS_INPUTS_64)
    movq xmm7, ARG1_64
    movq xmm1, ARG2_64
    shufps xmm1, xmm7, 0x73
TEST_END_64

TEST_BEGIN_64(SHUFPSv128v128imm8_many, 1)
TEST_INPUTS(0)
    shufps xmm7, xmm6, 0x2f
    shufps xmm6, xmm5, 0x57
    shufps xmm5, xmm4, 0xa6
    shufps xmm4, xmm3, 0xc3
    shufps xmm3, xmm2, 0x1d
    shufps xmm2, xmm1, 0xb8
    shufps xmm1, xmm0, 0x35
TEST_END_64
