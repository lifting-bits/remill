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

TEST_BEGIN(PUSHF, 1)
TEST_INPUTS(
    0)
    .byte 0x66, 0x9C;  // PUSHF (word)
TEST_END

TEST_BEGIN_64(PUSHFQ_64, 1)
TEST_INPUTS(
    0)
    pushfq
TEST_END_64

TEST_BEGIN(PUSHF_POPF, 1)
TEST_INPUTS(
    0)
    .byte 0x66, 0x9C;  // PUSHF (word)
    .byte 0x66, 0x9D;  // POPF (word)
TEST_END

TEST_BEGIN_64(PUSHFQ_POPFQ_64, 1)
TEST_INPUTS(
    0)
    pushfq
    popfq
TEST_END_64

TEST_BEGIN_64(PUSHFQ_SET_CPUID_POPFQ_64, 1)
TEST_INPUTS(
    0)
    pushfq
    or QWORD PTR [rsp], 0x200000
    popfq
TEST_END_64

TEST_BEGIN_64(PUSHFQ_UNSET_CPUID_POPFQ_64, 1)
TEST_INPUTS(
    0)
    pushfq
    or QWORD PTR [rsp], 0x200000
    popfq
    pushfq
    xor QWORD PTR [rsp], 0x200000
    popfq
TEST_END_64
