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

/* ORR  <Wd>, <Wn>, <Wm>{, <shift> #<amount>} */
TEST_BEGIN(ORR_32_LOG_SHIFT, orr_w9_w0_w1, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304)

    orr w9, w0, w1
TEST_END

TEST_BEGIN(ORR_32_LOG_SHIFT, orr_w9_w0_w1_lsl5, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304)

    orr w9, w0, w1, lsl #5
TEST_END

TEST_BEGIN(ORR_32_LOG_SHIFT, orr_w9_w0_w1_lsr5, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304)

    orr w9, w0, w1, lsr #5
TEST_END


TEST_BEGIN(ORR_32_LOG_SHIFT, orr_w9_w0_w1_ror5, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304)

    orr w9, w0, w1, ror #5
TEST_END

TEST_BEGIN(ORR_32_LOG_SHIFT, orr_w9_w0_w1_asr5, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304)

    orr w9, w0, w1, asr #5
TEST_END

/* ORR  <Xd>, <Xn>, <Xm>{, <shift> #<amount>} */
TEST_BEGIN(ORR_64_LOG_SHIFT, orr_x9_x0_x1, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFF00000000, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF00000000,
    0xFFFFFFFFFFFFFFFF, 0,
    0, 0xFFFFFFFFFFFFFFFF,
    0xfafbfbfdf1f2f3f4, 0xf1f2f3f4fafbfbfd,
    0x0a0b0c0d01020304, 0x010203040a0b0c0d)

    orr x9, x0, x1
TEST_END

TEST_BEGIN(ORR_64_LOG_SHIFT, orr_x9_x0_x1_lsl5, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFF00000000, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF00000000,
    0xFFFFFFFFFFFFFFFF, 0,
    0, 0xFFFFFFFFFFFFFFFF,
    0xfafbfbfdf1f2f3f4, 0xf1f2f3f4fafbfbfd,
    0x0a0b0c0d01020304, 0x010203040a0b0c0d)

    orr x9, x0, x1, lsl #5
TEST_END

TEST_BEGIN(ORR_64_LOG_SHIFT, orr_x9_x0_x1_lsr5, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304)

    orr x9, x0, x1, lsr #5
TEST_END

TEST_BEGIN(ORR_64_LOG_SHIFT, orr_x9_x0_x1_ror5, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304)

    orr x9, x0, x1, ror #5
TEST_END

TEST_BEGIN(ORR_64_LOG_SHIFT, orr_x9_x0_x1_asr5, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFF00000000, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF00000000,
    0xFFFFFFFFFFFFFFFF, 0,
    0, 0xFFFFFFFFFFFFFFFF,
    0xfafbfbfdf1f2f3f4, 0xf1f2f3f4fafbfbfd,
    0x0a0b0c0d01020304, 0x010203040a0b0c0d)

    orr x9, x0, x1, asr #5
TEST_END

