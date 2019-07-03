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

TEST_BEGIN_64(POPrsp_64_ADD8, 1)
TEST_INPUTS(0)
    push rsp
    add qword ptr [rsp], 8
    pop rsp
TEST_END_64

TEST_BEGIN_64(POPrsp_64, 1)
TEST_INPUTS(0)
    push rsp
    pop rsp
TEST_END_64

TEST_BEGIN_64(POPsp_64, 1)
TEST_INPUTS(0)
    push sp
    pop sp
TEST_END_64

TEST_BEGIN_64(POPmrsp64_64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 16]
    pop QWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(POPmrsp64offs_64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 16]
    pop QWORD PTR [rsp - 0x8]
TEST_END_64

TEST_BEGIN_64(POPmrsp16_64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 16]
    pop WORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(POPmrsp16offs_64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 16]
    pop WORD PTR [rsp - 0x8]
TEST_END_64

TEST_BEGIN_64(POPr16_64, 1)
TEST_INPUTS(
    0,
    0xFF,
    0xFFFF)
    lea rsp, [rsp - 16]
    mov rax, ARG1_64
    pop ax
TEST_END_64

TEST_BEGIN_64(POPr64_64, 1)
TEST_INPUTS(
    0,
    0xFF,
    0xFFFF,
    0xFFFFFFFF,
    0xFFFFFFFFFFFFFFFF)
    lea rsp, [rsp - 16]
    pop ARG1_64
TEST_END_64
