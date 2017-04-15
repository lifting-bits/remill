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

TEST_BEGIN(STOSB, 1)
TEST_INPUTS(
    0,
    1,
    0xAA,
    0xFF)

    mov eax, ARG1_32
#ifdef IN_TEST_GENERATOR
    .byte IF_64_BIT(0x48, ) 0x8d, 0x7c, 0x24, 0xf8
#else
    lea rdi, [rsp - 8]
#endif
    stosb
TEST_END

TEST_BEGIN(STOSW, 1)
TEST_INPUTS(
    0,
    1,
    0xAA,
    0xFF,
    0x4141,
    0xFFFF,
    0xFF00,
    0xF00F)

    mov eax, ARG1_32
#ifdef IN_TEST_GENERATOR
    .byte IF_64_BIT(0x48, ) 0x8d, 0x7c, 0x24, 0xf8
#else
    lea rdi, [rsp - 8]
#endif
    stosw
TEST_END

TEST_BEGIN(STOSD, 1)
TEST_INPUTS(
    0,
    1,
    0xAA,
    0xFF,
    0x4141,
    0xFFFF,
    0xFF00,
    0xF00F,
    0x41414141,
    0xFFFF0000,
    0xFFFFFFFF)

    mov eax, ARG1_32
#ifdef IN_TEST_GENERATOR
    .byte IF_64_BIT(0x48, ) 0x8d, 0x7c, 0x24, 0xf8
#else
    lea rdi, [rsp - 8]
#endif
    stosd
TEST_END

TEST_BEGIN_64(STOSQ_64, 1)
TEST_INPUTS(
    0,
    1,
    0xAA,
    0xFF,
    0x4141,
    0xFFFF,
    0xFF00,
    0xF00F,
    0x41414141,
    0xFFFF0000,
    0xFFFFFFFF,
    0x4141414141414141,
    0xFFFF0000FFFF0000,
    0xFFFFFFFFFFFFFFFF)

    mov rax, ARG1_64
    lea rdi, [rsp - 8]
    stosq
TEST_END_64
