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

TEST_BEGIN(MULal, 2)
TEST_IGNORE_FLAGS(ZF AF PF SF)
TEST_INPUTS(
    0, 0,
    0x7F, 0x7F,
    0xFF, 0x7F,
    0xFF, 0xFF)

    mov eax, ARG1_32
    mov ebx, ARG2_32

    mul bl
TEST_END

TEST_BEGIN_64(MULal_64, 2)
TEST_IGNORE_FLAGS(ZF AF PF SF)
TEST_INPUTS(
    0, 0,
    0x7F, 0x7F,
    0xFF, 0x7F,
    0xFF, 0xFF)

    mov rax, ARG1_64
    mov r8, ARG2_64

    mul r8b
TEST_END_64

TEST_BEGIN(MULax, 2)
TEST_IGNORE_FLAGS(ZF AF PF SF)
TEST_INPUTS(
    0, 0,
    1, 0x7FFF,
    1, 0xFFFF,
    0xFFFF, 0xFFFF)

    mov eax, ARG1_32
    mov ebx, ARG2_32

    mul bx
TEST_END

TEST_BEGIN(MULeax, 2)
TEST_IGNORE_FLAGS(ZF AF PF SF)
TEST_INPUTS(
    0, 0,
    1, 0x7FFF,
    1, 0xFFFF,
    0xFFFF, 0xFFFF,
    0xFFFFFFFF, 0xFFFF,
    0xFFFFFFFF, 0xFFFFFFFF)

    mov eax, ARG1_32
    mov ebx, ARG2_32

    mul ebx
TEST_END

TEST_BEGIN_64(MULrax_64, 2)
TEST_IGNORE_FLAGS(ZF AF PF SF)
TEST_INPUTS(
    0, 1,
    0xFFFF, 0xFFFF,
    0xFFFFFFFF, 0xFFFF,
    0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0x7FFFFFFF,
    0x7FFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF)

    mov rax, ARG1_64
    mov rbx, ARG2_64

    mul rbx
TEST_END_64
