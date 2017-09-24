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
TEST_BEGIN(MADD_32A_DP_3SRC, mul_w3_w0_w1_w2, 2)
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

    madd w3, ARG1_32, ARG2_32, wzr
TEST_END

/* MADD  <Wd>, <Wn>, <Wm>, <Wa> */
TEST_BEGIN(MADD_32A_DP_3SRC, madd_w3_w0_w1_w2, 3)
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

    madd w3, ARG1_32, ARG2_32, ARG3_32
    madd w4, ARG2_32, ARG3_32, ARG1_32
    madd w5, ARG1_32, ARG1_32, ARG1_32
TEST_END


/* MUL  <Wd>, <Wn>, <Wm> */
TEST_BEGIN(MADD_64A_DP_3SRC, mul_x3_x0_x1_x2, 2)
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

    madd x3, ARG1_64, ARG2_64, xzr
TEST_END

/* MADD  <Xd>, <Xn>, <Xm>, <Xa> */
TEST_BEGIN(MADD_64A_DP_3SRC, madd_x3_x0_x1_x2, 3)
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

    madd x3, ARG1_64, ARG2_64, ARG3_64
    madd x4, ARG2_64, ARG3_64, ARG1_64
    madd x5, ARG1_64, ARG1_64, ARG1_64
TEST_END
