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

TEST_BEGIN_64(PUSHrsp_64, 1)
TEST_INPUTS(0)
    push rsp
TEST_END_64

TEST_BEGIN_64(PUSHsp_64, 1)
TEST_INPUTS(0)
    push sp
TEST_END_64

TEST_BEGIN_64(PUSHmrsp64_64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 0x8]
    push QWORD PTR [rsp]
TEST_END_64


TEST_BEGIN_64(PUSHmrsp64offs_64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 0x8]
    push QWORD PTR [rsp - 0x8]
TEST_END_64

TEST_BEGIN_64(PUSHmrsp16_64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 0x8]
    push WORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(PUSHmrsp16offs_64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 0x8]
    push WORD PTR [rsp - 0x8]
TEST_END_64

TEST_BEGIN_64(PUSHr16_64, 1)
TEST_INPUTS(
    0,
    0xFF,
    0xFFFF)
    mov rax, ARG1_64
    push ax
TEST_END_64

TEST_BEGIN_64(PUSHr64_64, 1)
TEST_INPUTS(
    0,
    0xFF,
    0xFFFF,
    0xFFFFFFFF,
    0xFFFFFFFFFFFFFFFF)
    push ARG1_64
TEST_END_64
