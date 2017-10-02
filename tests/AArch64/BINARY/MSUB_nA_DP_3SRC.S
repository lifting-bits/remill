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

/* MUL  <Wd>, <Wn>, <Wm> */
TEST_BEGIN(MSUB_32A_DP_3SRC, msub_w3_w0_w1_w2, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 1,
    1, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xFFFFFFFF, 0,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304)

    msub w3, ARG1_32, ARG2_32, wzr
TEST_END

/* MSUB  <Wd>, <Wn>, <Wm>, <Wa> */
TEST_BEGIN(MSUB_32A_DP_3SRC, msub_w3_w0_w1_w2, 3)
TEST_INPUTS(
    0, 0, 0,
    0, 1, 0,
    1, 0, 0,
    1, 1, 0,
    0xFFFFFFFF, 1, 0,
    1, 0xFFFFFFFF, 0,
    0xFFFFFFFF, 0xFFFFFFFF, 0,
    0, 0xFFFFFFFF, 0,
    0xFFFFFFFF, 0, 0,
    0xfafbfbfd, 0xf1f2f3f4, 0,
    0x0a0b0c0d, 0x01020304, 0)

    msub w3, ARG1_32, ARG2_32, ARG3_32
    msub w4, ARG2_32, ARG3_32, ARG1_32
    msub w5, ARG1_32, ARG1_32, ARG1_32
TEST_END


/* MUL  <Wd>, <Wn>, <Wm> */
TEST_BEGIN(MSUB_64A_DP_3SRC, msub_x3_x0_x1_x2, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 1,
    1, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xFFFFFFFF, 0,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304)

    msub x3, ARG1_64, ARG2_64, xzr
TEST_END

/* MSUB  <Xd>, <Xn>, <Xm>, <Xa> */
TEST_BEGIN(MSUB_64A_DP_3SRC, msub_x3_x0_x1_x2, 3)
TEST_INPUTS(
    0, 0, 0,
    0, 1, 0,
    1, 0, 0,
    1, 1, 0,
    0xFFFFFFFF, 1, 0,
    1, 0xFFFFFFFF, 0,
    0xFFFFFFFF, 0xFFFFFFFF, 0,
    0, 0xFFFFFFFF, 0,
    0xFFFFFFFF, 0, 0,
    0xfafbfbfd, 0xf1f2f3f4, 0,
    0x0a0b0c0d, 0x01020304, 0)

    msub x3, ARG1_64, ARG2_64, ARG3_64
    msub x4, ARG2_64, ARG3_64, ARG1_64
    msub x5, ARG1_64, ARG1_64, ARG1_64
TEST_END
