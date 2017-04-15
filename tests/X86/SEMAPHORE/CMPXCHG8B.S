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

TEST_BEGIN_MEM_64(CMPXCHG8Bm64edxeax_0, 3)
TEST_INPUTS(
    0, 0, 0,
    0, 0, 1,
    0, 1, 0,
    0, 1, 1,
    1, 0, 0,
    1, 0, 1,
    1, 1, 0,
    1, 1, 1)

    data16 push 0
    push ARG1_16
    data16 push 0
    push ARG2_16

    push ARG3_64
    mov edx, 0
    pop rax

    mov ebx, 0
    mov ecx, 0
    not rbx
    not rcx
    cmpxchg8b QWORD PTR [rsp]
TEST_END_MEM_64

TEST_BEGIN_MEM_64(CMPXCHG8Bm64edxeax_1, 3)
TEST_INPUTS(
    0, 0, 0,
    0, 0, 1,
    0, 1, 0,
    0, 1, 1,
    1, 0, 0,
    1, 0, 1,
    1, 1, 0,
    1, 1, 1)

    data16 push 0
    push ARG1_16
    data16 push 0
    push ARG2_16

    push ARG3_64
    mov eax, 0
    pop rdx

    mov ebx, 0
    mov ecx, 0
    not rbx
    not rcx
    cmpxchg8b QWORD PTR [rsp]
TEST_END_MEM_64

