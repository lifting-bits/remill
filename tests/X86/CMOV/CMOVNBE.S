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

TEST_BEGIN(CMOVNBEr16r16, 1)
TEST_INPUTS(
    0x4141414141414141)

    cmovnbe ARG2_16, ARG1_16
TEST_END

TEST_BEGIN(CMOVNBEr32r32, 1)
TEST_INPUTS(
    0x4141414141414141)

    cmovnbe ARG2_32, ARG1_32
TEST_END

TEST_BEGIN_64(CMOVNBEr64r64, 1)
TEST_INPUTS(
    0x4141414141414141)

    cmovnbe ARG2_64, ARG1_64
TEST_END_64

TEST_BEGIN_64(CMOVNBEr16m16, 1)
TEST_INPUTS(
    0x4141414141414141)

    cmovnbe ARG2_16, WORD PTR [rsp - 8]
TEST_END_64

TEST_BEGIN_64(CMOVNBEr32m32, 1)
TEST_INPUTS(
    0x4141414141414141)

    cmovnbe ARG2_32, DWORD PTR [rsp - 8]
TEST_END_64

TEST_BEGIN_64(CMOVNBEr64m64, 1)
TEST_INPUTS(
    0x4141414141414141)

    cmovnbe ARG2_64, QWORD PTR [rsp - 8]
TEST_END_64
