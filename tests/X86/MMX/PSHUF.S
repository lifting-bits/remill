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

TEST_BEGIN_64(PSHUFBv64v64, 2)
TEST_INPUTS(
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0x0000000000000000,
    0x0000000000000000, 0xFFFFFFFFFFFFFFFF,
    0x8080808080808080, 0x0101010101010101,
    0x0101010101010101, 0x8080808080808080,
    0x8001800180018001, 0x0180018001800180)
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pshufb mm0, mm1
TEST_END_64

TEST_BEGIN_64(PSHUFBv128v128, 2)
TEST_INPUTS(
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0x0000000000000000,
    0x0000000000000000, 0xFFFFFFFFFFFFFFFF,
    0x8080808080808080, 0x0101010101010101,
    0x0101010101010101, 0x8080808080808080,
    0x8001800180018001, 0x0180018001800180)
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pshufb xmm2, xmm1
    pshufb xmm4, xmm1
    pshufb xmm3, xmm0
    pshufb xmm5, xmm0
TEST_END_64

TEST_BEGIN_64(PSHUFWv64v64, 2)
TEST_INPUTS(
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0x0000000000000000,
    0x0000000000000000, 0xFFFFFFFFFFFFFFFF,
    0x8080808080808080, 0x0101010101010101,
    0x0101010101010101, 0x8080808080808080,
    0x8001800180018001, 0x0180018001800180)
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pshufw mm0, mm1, 0
    pshufw mm0, mm1, 0x22
    pshufw mm0, mm1, 0x8F
    pshufw mm0, mm1, 0x54
TEST_END_64

