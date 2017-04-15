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

TEST_BEGIN(BSRr16r16, 1)
TEST_IGNORE_FLAGS(CF OF SF AF PF)
TEST_INPUTS(
    0,
    1,
    0x8000,
    0x8001,
    0xFFFF,
    0x0080,
    0x0800)

    mov eax, ARG1_32
    bsr dx, ax
TEST_END

TEST_BEGIN(BSRr32r32, 1)
TEST_IGNORE_FLAGS(CF OF SF AF PF)
TEST_INPUTS(
    0,
    1,
    0x80000000,
    0x80000001,
    0xFFFFFFFF,
    0x00000080,
    0x08000000)

    mov eax, ARG1_32
    bsr edx, eax
TEST_END

TEST_BEGIN_64(BSRr64r64, 1)
TEST_IGNORE_FLAGS(CF OF SF AF PF)
TEST_INPUTS(
    0,
    1,
    0x8000000000000000,
    0x8000000000000001,
    0xFFFFFFFFFFFFFFFF,
    0x0000000000000080,
    0x0800000000000000)

    mov rax, ARG1_64
    bsr rdx, rax
TEST_END_64
