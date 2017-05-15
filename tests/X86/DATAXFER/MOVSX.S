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

TEST_BEGIN_64(MOVSXr16r8, 1)
TEST_INPUTS(
    0x70, 0xFFFFFFFFFFFFFFFF,
    0x80, 0xFFFFFFFFFFFFFFFF)

    movsx ARG2_16, ARG1_8
TEST_END_64

TEST_BEGIN(MOVSXr32r16, 2)
TEST_INPUTS(
    0x7000, 0xFFFFFFFFFFFFFFFF,
    0x8000, 0xFFFFFFFFFFFFFFFF)

    movsx ARG2_32, ARG1_16
TEST_END

TEST_BEGIN_64(MOVSXr32r8, 2)
TEST_INPUTS(
    0x70, 0xFFFFFFFFFFFFFFFF,
    0x80, 0xFFFFFFFFFFFFFFFF)

    movsx ARG2_32, ARG1_8
TEST_END_64

TEST_BEGIN_64(MOVSXr64r8, 2)
TEST_INPUTS(
    0x70, 0xFFFFFFFFFFFFFFFF,
    0x80, 0xFFFFFFFFFFFFFFFF)

    movsx ARG2_64, ARG1_8
TEST_END_64

TEST_BEGIN_64(MOVSXr64r16, 2)
TEST_INPUTS(
    0x7000, 0xFFFFFFFFFFFFFFFF,
    0x8000, 0xFFFFFFFFFFFFFFFF)

    movsx ARG2_64, ARG1_16
TEST_END_64

TEST_BEGIN_64(MOVSXr64r32, 2)
TEST_INPUTS(
    0x70000000, 0xFFFFFFFFFFFFFFFF,
    0x80000000, 0xFFFFFFFFFFFFFFFF)

    mov edi, ARG1_32

    // movsx rsi, edi
    .byte 0x48, 0x63, 0xf7

TEST_END_64
