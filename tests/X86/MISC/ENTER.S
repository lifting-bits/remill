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

TEST_BEGIN_64(ENTER_0_0_64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 0, 0
TEST_END_64

TEST_BEGIN_64(ENTER_0_1_64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 0, 1
TEST_END_64

TEST_BEGIN_64(ENTER_1_0_64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 1, 0
TEST_END_64

TEST_BEGIN_64(ENTER_1_1_64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 1, 1
TEST_END_64

TEST_BEGIN_64(ENTER_1_32_64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 1, 32
TEST_END_64

TEST_BEGIN_64(ENTER_1_31_64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 1, 31
TEST_END_64

TEST_BEGIN_64(ENTER_8_31_64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 8, 31
TEST_END_64

TEST_BEGIN_64(ENTER_8_8_64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 8, 8
TEST_END_64

TEST_BEGIN_64(ENTER_19_8_64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 19, 8
TEST_END_64
