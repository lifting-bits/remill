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

TEST_BEGIN(DECr8, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF)

    mov eax, ARG1_32
    dec al
TEST_END

TEST_BEGIN_64(DECr8_64, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF)

    dec ARG1_8
TEST_END_64

TEST_BEGIN(DECr16, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF)

    dec ARG1_16
TEST_END

TEST_BEGIN(DECr32, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF)

    dec ARG1_32
TEST_END

TEST_BEGIN_64(DECr64_64, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF,
    0x7FFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF)

    dec ARG1_64
TEST_END_64
