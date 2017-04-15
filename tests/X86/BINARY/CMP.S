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

TEST_BEGIN(CMPr8r8, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0, 0xFF,
    0x10, 0, /* AF */
    0xFF, 0x11 /* PF */)

    mov ax, ARG1_16
    mov bx, ARG2_16
    cmp al, bl
TEST_END

TEST_BEGIN(CMPr16r16, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0, 0xFFFF,
    0x10, 0, /* AF */
    0xFF, 0x11 /* PF */)

    cmp ARG1_16, ARG2_16
TEST_END

TEST_BEGIN(CMPr16i16, 1)
TEST_INPUTS(
    0,
    1,
    0x7FFF,
    0xFFFF)

    cmp ARG1_16, 0xFFFF
TEST_END

TEST_BEGIN(CMPr32r32, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0, 0xFFFFFFFF,
    0x10, 0, /* AF */
    0xFF, 0x11 /* PF */)

    cmp ARG1_32, ARG2_32
TEST_END

TEST_BEGIN(CMPr32i32, 1)
TEST_INPUTS(
    0,
    1,
    0x7FFFFFFF,
    0xFFFFFFFF)

    cmp ARG1_32, 0xFFFFFFFF
TEST_END

TEST_BEGIN_64(CMPr64r64_64, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0, 0xFFFFFFFFFFFFFFFF,
    1, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 1,
    0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF,
    0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF)

    cmp ARG1_64, ARG2_64
TEST_END_64

TEST_BEGIN_64(CMPr64s32_64, 1)
TEST_INPUTS(
    0,
    1,
    0xFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0x7FFFFFFFFFFFFFFF)

    .byte 0x48;  /* REX.W */
    cmp ARG1_32, 0xFFFFFFFF
TEST_END_64

TEST_BEGIN_64(CMPr64u32_64, 1)
TEST_INPUTS(
    0,
    1,
    0xFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0x7FFFFFFFFFFFFFFF)

    cmp ARG1_64, 0x7FFFFFFF
TEST_END_64

