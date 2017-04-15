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

TEST_BEGIN(DIVax, 2)
TEST_IGNORE_FLAGS(CF OF SF ZF AF PF)
TEST_INPUTS(
    0, 0,
    1, 0,
    0, 1,
    1, 1,
    1, 2,
    0xFFFF, 1,
    0xFFFF, 2,
    0xFFFF, 0xFF,
    0xFFFF, 0xF7,
    0x7FFF, 1,
    0x7FFF, 2,
    0x7FFF, 0xFF,
    0x7FFF, 0xF7)

    mov eax, ARG1_32
    mov ebx, ARG2_32

    div bl
TEST_END

TEST_BEGIN_64(DIVax_64, 2)
TEST_IGNORE_FLAGS(CF OF SF ZF AF PF)
TEST_INPUTS(
    0, 0,
    1, 0,
    0, 1,
    1, 1,
    1, 2,
    0xFFFF, 1,
    0xFFFF, 2,
    0xFFFF, 0xFF,
    0xFFFF, 0xF7,
    0x7FFF, 1,
    0x7FFF, 2,
    0x7FFF, 0xFF,
    0x7FFF, 0xF7)

    mov rax, ARG1_64
    mov r8, ARG2_64

    div r8b
TEST_END_64

TEST_BEGIN(DIVdxax, 3)
TEST_IGNORE_FLAGS(CF OF SF ZF AF PF)
TEST_INPUTS(
    0, 0, 0,
    1, 0, 0,
    0, 1, 0,
    1, 1, 0,
    1, 2, 0,
    0xFFFF, 1, 0,
    0xFFFF, 2, 0,
    0xFFFF, 0xFF, 0,
    0xFFFF, 0xF7, 0,
    0xFFFF, 1, 0xFFFF,
    0xFFFF, 2, 0xFFFF,
    0xFFFF, 0xFF, 0xFFFF,
    0xFFFF, 0xF7, 0xFFFF,
    0xFFFF, 1, 0x7FFF,
    0xFFFF, 2, 0x7FFF,
    0xFFFF, 0xFF, 0x7FFF,
    0xFFFF, 0xF7, 0x7FFF)

    mov eax, ARG1_32
    mov ebx, ARG2_32
    mov edx, ARG3_32

    div bx
TEST_END

TEST_BEGIN(DIVedxeax, 3)
TEST_IGNORE_FLAGS(CF OF SF ZF AF PF)
TEST_INPUTS(
    0xFFFF, 0xFF, 0,
    0xFFFF, 0xF7, 0,
    0xFFFF, 0xFF, 0xFFFF,
    0xFFFF, 0xF7, 0xFFFF,
    0xFFFF, 0xFF, 0x7FFF,
    0xFFFF, 0xF7, 0x7FFF,
    0xFFFFFFFF, 0xFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xF7, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFF, 0x7FFFFFFF,
    0xFFFFFFFF, 0xF7, 0x7FFFFFFF)

    mov eax, ARG1_32
    mov ebx, ARG2_32
    mov edx, ARG3_32

    div ebx
TEST_END

TEST_BEGIN_64(DIVrdxrax_64, 3)
TEST_IGNORE_FLAGS(CF OF SF ZF AF PF)
TEST_INPUTS(
    0xFFFF, 0xFF, 0,
    0xFFFF, 0xF7, 0,
    0xFFFF, 0xFF, 0xFFFF,
    0xFFFF, 0xF7, 0xFFFF,
    0xFFFF, 0xFF, 0x7FFF,
    0xFFFF, 0xF7, 0x7FFF,
    0xFFFFFFFF, 0xFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xF7, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFF, 0x7FFFFFFF,
    0xFFFFFFFF, 0xF7, 0x7FFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0xFF, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0xF7, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0xFF, 0x7FFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0xF7, 0x7FFFFFFFFFFFFFFF)

    mov eax, ARG1_32
    mov ebx, ARG2_32
    mov edx, ARG3_32

    div ebx
TEST_END_64
