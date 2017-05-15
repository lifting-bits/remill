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

TEST_BEGIN(SBBal, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF)

    mov eax, ARG1_32
    sbb al, 1
TEST_END

TEST_BEGIN(SBBax, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF)

    mov eax, ARG1_32
    sbb ax, 1
TEST_END

TEST_BEGIN(SBBeax, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF)

    mov eax, ARG1_32
    sbb eax, 1
TEST_END

TEST_BEGIN(SBBr8i8, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF)

    mov ebx, ARG1_32
    sbb bl, 1
TEST_END

TEST_BEGIN_64(SBBr8u8_64, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF)

    mov r8, ARG1_64
    sbb r8b, 0x7F
TEST_END_64

TEST_BEGIN_64(SBBr8s8_64, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF)

    mov r8, ARG1_64
    sbb r8b, 0xFF /* Sign-extended to 64-bits */
TEST_END_64

TEST_BEGIN(SBBr8r8, 2)
TEST_INPUTS(
    0, 0,
    1, 0,
    0xFF, 1,
    0x7F, 1,
    0x7F, 0xFF,
    0xFF, 0xFF)

    mov ebx, ARG1_32
    mov eax, ARG2_32
    sbb bl, al
TEST_END

TEST_BEGIN_64(SBBr8r8_64, 2)
TEST_INPUTS(
    0, 0,
    1, 0,
    0xFF, 1,
    0x7F, 1,
    0x7F, 0xFF,
    0xFF, 0xFF)

    mov r8, ARG1_64
    mov r9, ARG2_64
    sbb r9b, r8b
TEST_END_64

TEST_BEGIN(SBBr16u8, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF)

    mov ebx, ARG1_32
    sbb bx, 0x7F
TEST_END

TEST_BEGIN(SBBr16s8, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF)

    mov ebx, ARG1_32
    sbb bx, 0xFF /* Sign-extended to 16-bits */
TEST_END

TEST_BEGIN(SBBr16i16, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF)

    mov ebx, ARG1_32
    sbb bx, 0xFFFF
TEST_END

TEST_BEGIN(SBBr16r16, 2)
TEST_INPUTS(
    0, 0,
    1, 0,
    0xFF, 1,
    0x7F, 1,
    0x7F, 0xFF,
    0xFF, 0xFF,
    0x7FFF, 1,
    0x7FFF, 0xFFFF,
    0xFFFF, 0xFFFF)

    mov ebx, ARG1_32
    mov edx, ARG2_32
    sbb bx, dx
TEST_END

TEST_BEGIN(SBBr32u8, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF)

    mov ebx, ARG1_32
    sbb ebx, 0x7F
TEST_END

TEST_BEGIN(SBBr32s8, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF)

    mov ebx, ARG1_32
    sbb ebx, 0xFF
TEST_END

TEST_BEGIN(SBBr32i32, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF)

    mov ebx, ARG1_32
    sbb ebx, 0x7FFFFFFF
TEST_END

TEST_BEGIN(SBBr32r32, 2)
TEST_INPUTS(
    0, 0, /* ZF */
    1, 0,
    0xFFFFFFFF, 1, /* OF, CF */
    0xFFFFFFFF, 0xFFFFFFFF, /* OF */
    0x7FFFFFFF, 1, /* SF */
    0, 0x10, /* AF */
    0x7F, 0x10 /* PF */)

    sbb ARG1_32, ARG2_32
TEST_END

TEST_BEGIN_64(SBBr64u8_64, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF,
    0x7FFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF)

    sbb ARG1_64, 0x7F
TEST_END_64

TEST_BEGIN_64(SBBr64s8_64, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF,
    0x7FFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF)

    sbb ARG1_64, 0xFF /* Sign-extended */
TEST_END_64

TEST_BEGIN_64(SBBr64u32_64, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF,
    0x7FFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF)

    sbb ARG1_64, 0x7FFFFFFF
TEST_END_64

TEST_BEGIN_64(SBBr64s32_64, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF,
    0x7FFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF)

    .byte 0x48;  /* REX.W */
    sbb ARG1_32, 0xFFFFFFFF /* Sign-extended */
TEST_END_64

TEST_BEGIN_64(SBBr64r64_64, 2)
TEST_INPUTS(
    0, 0, /* ZF */
    1, 0,
    0xFFFFFFFF, 1, /* OF, CF */
    0xFFFFFFFF, 0xFFFFFFFF, /* OF */
    0x7FFFFFFF, 1, /* SF */
    0, 0x10, /* AF */
    0x7F, 0x10, /* PF */
    0x7FFFFFFFFFFFFFFF, 1,
    0x7FFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF,
    0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF)

    sbb ARG1_64, ARG2_64
TEST_END_64
