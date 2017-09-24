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

/* UMULL  <Xd>, <Wn>, <Wm> */
TEST_BEGIN(UMADDL_64WA_DP_3SRC, umull_x3_w0_w1, 2)
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

    umaddl x3, ARG1_32, ARG2_32, xzr
TEST_END

/* UMADDL  <Xd>, <Wn>, <Wm>, <Xa> */
TEST_BEGIN(UMADDL_64WA_DP_3SRC, umaddl_x3_w0_w1_x2, 3)
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

    umaddl x3, ARG1_32, ARG2_32, ARG3_64
    umaddl x4, ARG1_32, ARG1_32, ARG1_64
    umaddl x5, ARG2_32, ARG2_32, ARG2_64
TEST_END
