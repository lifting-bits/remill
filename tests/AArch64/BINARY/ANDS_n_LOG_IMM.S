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

/* ANDS  <Wd>, <Wn>, #<imm> */
TEST_BEGIN(ANDS_32S_LOG_IMM, ands_w9_w0_0x10101010, 1)
TEST_INPUTS(
    0,
    1,
    0xFFFFFFFF,
    0xfafbfbfd,
    0xf1f2f3f4,
    0x0a0b0c0d,
    0x01020304)

    ands w9, w0, #0x10101010
TEST_END

/* ANDS  <Xd>, <Xn>, #<imm> */
TEST_BEGIN(ANDS_64S_LOG_IMM, ands_x9_x0_0x1010101010101010, 1)
TEST_INPUTS(
    0,
    1,
    0xFFFFFFFF,
    0xfafbfbfd,
    0xf1f2f3f4,
    0x0a0b0c0d,
    0x01020304)

    ands x9, x0, #0x1010101010101010
TEST_END

TEST_BEGIN(ANDS_64S_LOG_IMM, ands_x9_x0_0xfff80007ffffffff, 1)
TEST_INPUTS(
    0,
    1,
    0xFFFFFFFF,
    0xfafbfbfd,
    0xf1f2f3f4,
    0x0a0b0c0d,
    0x01020304)

    ands x9, x0, #0xfff80007ffffffff
TEST_END

