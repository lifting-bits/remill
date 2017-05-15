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

TEST_BEGIN_64(MOVZXr16r8, 1)
TEST_INPUTS(
    0x70, 0xFFFFFFFFFFFFFFFF,
    0x80, 0xFFFFFFFFFFFFFFFF)

    movzx ARG2_16, ARG1_8
TEST_END_64

TEST_BEGIN(MOVZXr32r16, 2)
TEST_INPUTS(
    0x7000, 0xFFFFFFFFFFFFFFFF,
    0x8000, 0xFFFFFFFFFFFFFFFF)

    movzx ARG2_32, ARG1_16
TEST_END

TEST_BEGIN_64(MOVZXr32r8, 2)
TEST_INPUTS(
    0x70, 0xFFFFFFFFFFFFFFFF,
    0x80, 0xFFFFFFFFFFFFFFFF)

    movzx ARG2_32, ARG1_8
TEST_END_64

TEST_BEGIN_64(MOVZXr64r8, 2)
TEST_INPUTS(
    0x70, 0xFFFFFFFFFFFFFFFF,
    0x80, 0xFFFFFFFFFFFFFFFF)

    movzx ARG2_64, ARG1_8
TEST_END_64

TEST_BEGIN_64(MOVZXr64r16, 2)
TEST_INPUTS(
    0x7000, 0xFFFFFFFFFFFFFFFF,
    0x8000, 0xFFFFFFFFFFFFFFFF)

    movzx ARG2_64, ARG1_16
TEST_END_64

