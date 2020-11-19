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

TEST_BEGIN_MEM(CMPXCHGm8r8al, 3)
TEST_INPUTS(
    0, 0, 0,
    0, 0, 1,
    0, 1, 0,
    0, 1, 1,
    1, 0, 0,
    1, 0, 1,
    1, 1, 0,
    1, 1, 1,
    0xFFFFFFFF, 0, 0x41414141,
    0xFFFFFFFF, 0xFFFFFFFF, 0x41414141)

    mov eax, ARG1_32
    mov ebx, ARG2_32
    mov DWORD PTR [rsp - 4], ARG3_32
    cmpxchg BYTE PTR [rsp - 4], bl
TEST_END_MEM

TEST_BEGIN(CMPXCHGr8r8al, 3)
TEST_INPUTS(
    0, 0, 0,
    0, 0, 1,
    0, 1, 0,
    0, 1, 1,
    1, 0, 0,
    1, 0, 1,
    1, 1, 0,
    1, 1, 1,
    0xFFFFFFFF, 0, 0x41414141,
    0xFFFFFFFF, 0xFFFFFFFF, 0x41414141)

    mov eax, ARG1_32
    mov ebx, ARG2_32
    cmpxchg ARG3_8, bl
TEST_END

TEST_BEGIN_MEM(CMPXCHGm16r16ax, 3)
TEST_INPUTS(
    0, 0, 0,
    0, 0, 1,
    0, 1, 0,
    0, 1, 1,
    1, 0, 0,
    1, 0, 1,
    1, 1, 0,
    1, 1, 1,
    0xFFFFFFFF, 0, 0x41414141,
    0xFFFFFFFF, 0xFFFFFFFF, 0x41414141)

    mov eax, ARG1_32
    mov ebx, ARG2_32
    mov DWORD PTR [rsp - 4], ARG3_32
    cmpxchg WORD PTR [rsp - 4], bx
TEST_END_MEM

TEST_BEGIN(CMPXCHGr16r16ax, 3)
TEST_INPUTS(
    0, 0, 0,
    0, 0, 1,
    0, 1, 0,
    0, 1, 1,
    1, 0, 0,
    1, 0, 1,
    1, 1, 0,
    1, 1, 1,
    0xFFFFFFFF, 0, 0x41414141,
    0xFFFFFFFF, 0xFFFFFFFF, 0x41414141)

    mov eax, ARG1_32
    mov ebx, ARG2_32
    cmpxchg ARG3_16, bx
TEST_END

TEST_BEGIN_MEM(CMPXCHGm32r32eax, 3)
TEST_INPUTS(
    0, 0, 0,
    0, 0, 1,
    0, 1, 0,
    0, 1, 1,
    1, 0, 0,
    1, 0, 1,
    1, 1, 0,
    1, 1, 1,
    0xFFFFFFFF, 0, 0x41414141,
    0xFFFFFFFF, 0xFFFFFFFF, 0x41414141)

    mov eax, ARG1_32
    mov ebx, ARG2_32
    mov DWORD PTR [rsp - 4], ARG3_32
    cmpxchg DWORD PTR [rsp - 4], ebx
TEST_END_MEM

TEST_BEGIN(CMPXCHGr32r32eax, 3)
TEST_INPUTS(
    0, 0, 0,
    0, 0, 1,
    0, 1, 0,
    0, 1, 1,
    1, 0, 0,
    1, 0, 1,
    1, 1, 0,
    1, 1, 1,
    0xFFFFFFFF, 0, 0x41414141,
    0xFFFFFFFF, 0xFFFFFFFF, 0x41414141)

    mov eax, ARG1_32
    mov ebx, ARG2_32
    cmpxchg ARG3_32, ebx
TEST_END

TEST_BEGIN_MEM_64(CMPXCHGm64r64rax, 3)
TEST_INPUTS(
    0, 0, 0,
    0, 0, 1,
    0, 1, 0,
    0, 1, 1,
    1, 0, 0,
    1, 0, 1,
    1, 1, 0,
    1, 1, 1,
    0xFFFFFFFF, 0, 0x41414141,
    0xFFFFFFFF, 0xFFFFFFFF, 0x41414141,
    0xFFFFFFFFFFFFFFFF, 0, 0x4141414141414141,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x4141414141414141)

    mov rax, ARG1_64
    mov rbx, ARG2_64
    mov QWORD PTR [rsp - 8], ARG3_64
    cmpxchg QWORD PTR [rsp - 8], rbx
TEST_END_MEM_64

TEST_BEGIN_64(CMPXCHGr64r64rax, 3)
TEST_INPUTS(
    0, 0, 0,
    0, 0, 1,
    0, 1, 0,
    0, 1, 1,
    1, 0, 0,
    1, 0, 1,
    1, 1, 0,
    1, 1, 1,
    0xFFFFFFFF, 0, 0x41414141,
    0xFFFFFFFF, 0xFFFFFFFF, 0x41414141,
    0xFFFFFFFFFFFFFFFF, 0, 0x4141414141414141,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x4141414141414141)

    mov rax, ARG1_64
    mov rbx, ARG2_64
    cmpxchg ARG3_64, rbx
TEST_END_64

TEST_BEGIN_64(CMPXCHG_issue376, 3)
TEST_INPUTS(
    0x4141414141414141, 0x4141414141414141, 0x4141414141414141,
    0x4141414141414141, 0x4141414141414141, 0xFFFFFFFFFFFFFFFF,
    0x4141414141414141, 0xFFFFFFFFFFFFFFFF, 0x4141414141414141,
    0x4141414141414141, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0x4141414141414141, 0x4141414141414141,
    0xFFFFFFFFFFFFFFFF, 0x4141414141414141, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x4141414141414141,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF)

    mov rax, ARG1_64
    mov rbx, ARG2_64
    mov rcx, ARG3_64
    cmpxchg ecx, ebx
TEST_END_64
