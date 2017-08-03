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

/* SUB  <Wd>, <Wn>, <Wm>{, <shift> #<amount>} */
TEST_BEGIN(SUB_32_ADDSUB_SHIFT, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0x0a0b0c0d, 0x01020304)

    sub w0, w0, w1
TEST_END

TEST_BEGIN(SUB_32_ADDSUB_SHIFT_lsl5, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0x0a0b0c0d, 0x01020304)

    sub w0, w0, w1, lsl 5
TEST_END

TEST_BEGIN(SUB_32_ADDSUB_SHIFT_lsr5, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0x0a0b0c0d, 0x01020304)

    sub w0, w0, w1, lsr 5
TEST_END

/* Note: ROR is not allowed here */

TEST_BEGIN(SUB_32_ADDSUB_SHIFT_asr5, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0x0a0b0c0d, 0x01020304)

    sub w0, w0, w1, asr 5
TEST_END
