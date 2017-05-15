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

TEST_BEGIN(XORal, 1)
TEST_IGNORE_FLAGS(AF)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF)

    mov eax, ARG1_32
    xor al, 1
TEST_END

TEST_BEGIN(XORax, 1)
TEST_IGNORE_FLAGS(AF)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF)

    mov eax, ARG1_32
    xor ax, 1
TEST_END

TEST_BEGIN(XOReax, 1)
TEST_IGNORE_FLAGS(AF)
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
    xor eax, 1
TEST_END

TEST_BEGIN(XORr8i8, 1)
TEST_IGNORE_FLAGS(AF)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF)

    mov ebx, ARG1_32
    xor bl, 1
TEST_END

TEST_BEGIN_64(XORr8u8_64, 1)
TEST_IGNORE_FLAGS(AF)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF)

    mov r8, ARG1_64
    xor r8b, 0x7F
TEST_END_64

TEST_BEGIN_64(XORr8s8_64, 1)
TEST_IGNORE_FLAGS(AF)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF)

    mov r8, ARG1_64
    xor r8b, 0xFF /* Sign-extended to 64-bits */
TEST_END_64

TEST_BEGIN(XORr8r8, 2)
TEST_IGNORE_FLAGS(AF)
TEST_INPUTS(
    0, 0,
    1, 0,
    0xFF, 1,
    0x7F, 1,
    0x7F, 0xFF,
    0xFF, 0xFF)

    mov ebx, ARG1_32
    mov eax, ARG2_32
    xor bl, al
TEST_END

TEST_BEGIN_64(XORr8r8_64, 1)
TEST_IGNORE_FLAGS(AF)
TEST_INPUTS(
    0, 0,
    1, 0,
    0xFF, 1,
    0x7F, 1,
    0x7F, 0xFF,
    0xFF, 0xFF)

    xor ARG1_8, ARG2_8
TEST_END_64

TEST_BEGIN(XORr16u8, 1)
TEST_IGNORE_FLAGS(AF)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF)

    xor ARG1_16, 0x7F
TEST_END

TEST_BEGIN(XORr16s8, 1)
TEST_IGNORE_FLAGS(AF)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF)

    xor ARG1_16, 0xFF /* Sign-extended to 16-bits */
TEST_END

TEST_BEGIN(XORr16i16, 1)
TEST_IGNORE_FLAGS(AF)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF)

    xor ARG1_16, 0xFFFF
TEST_END

TEST_BEGIN(XORr16r16, 2)
TEST_IGNORE_FLAGS(AF)
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

    xor ARG1_16, ARG2_16
TEST_END

TEST_BEGIN(XORr32u8, 1)
TEST_IGNORE_FLAGS(AF)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF)

    xor ARG1_32, 0x7F
TEST_END

TEST_BEGIN(XORr32s8, 1)
TEST_IGNORE_FLAGS(AF)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF)

    xor ARG1_32, 0xFF
TEST_END

TEST_BEGIN(XORr32i32, 1)
TEST_IGNORE_FLAGS(AF)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF)

    xor ARG1_32, 0x7FFFFFFF
TEST_END

TEST_BEGIN(XORr32r32, 2)
TEST_IGNORE_FLAGS(AF)
TEST_INPUTS(
    0, 0,
    1, 0,
    0xFFFFFFFF, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0x7FFFFFFF, 1,
    0, 0x10,
    0x7F, 0x10)

    xor ARG1_32, ARG2_32
TEST_END

TEST_BEGIN_64(XORr64u8_64, 1)
TEST_IGNORE_FLAGS(AF)
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

    xor ARG1_64, 0x7F
TEST_END_64

TEST_BEGIN_64(XORr64s8_64, 1)
TEST_IGNORE_FLAGS(AF)
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

    xor ARG1_64, 0xFF /* Sign-extended */
TEST_END_64

TEST_BEGIN_64(XORr64u32_64, 1)
TEST_IGNORE_FLAGS(AF)
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

    xor ARG1_64, 0x7FFFFFFF
TEST_END_64

TEST_BEGIN_64(XORr64s32_64, 1)
TEST_IGNORE_FLAGS(AF)
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
    xor ARG1_32, 0xFFFFFFFF /* Sign-extended */
TEST_END_64

TEST_BEGIN_64(XORr64r64_64, 2)
TEST_IGNORE_FLAGS(AF)
TEST_INPUTS(
    0, 0,
    1, 0,
    0xFFFFFFFF, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0x7FFFFFFF, 1,
    0, 0x10,
    0x7F, 0x10,
    0x7FFFFFFFFFFFFFFF, 1,
    0x7FFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF,
    0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF)

    xor ARG1_64, ARG2_64
TEST_END_64

TEST_BEGIN(PXORr64r64_64, 1)
TEST_IGNORE_FLAGS(AF)
TEST_INPUTS()

    pxor xmm0, xmm1
    pxor xmm2, xmm3
    pxor xmm4, xmm5
TEST_END
