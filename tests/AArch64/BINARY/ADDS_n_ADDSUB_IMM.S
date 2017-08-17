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

/* SUBS  <Wd>, <Wn|WSP>, #<imm>{, <shift>} */
TEST_BEGIN(ADDS_32S_ADDSUB_IMM, adds_x9_w0_1, 1)
TEST_INPUTS(
    0,
    1,
    0xFFFFFFFF,
    0xfafbfbfd,
    0xf1f2f3f4,
    0x0a0b0c0d,
    0x01020304)

    adds w9, w0, #0x1
TEST_END

TEST_BEGIN(ADDS_32S_ADDSUB_IMM, adds_x9_w0_fff, 1)
TEST_INPUTS(
    0,
    1,
    0xFFFFFFFF,
    0xfafbfbfd,
    0xf1f2f3f4,
    0x0a0b0c0d,
    0x01020304)

    adds w9, w0, #0xfff
TEST_END

TEST_BEGIN(ADDS_32S_ADDSUB_IMM, adds_x9_w0_0FF_lsl12, 1)
TEST_INPUTS(
    0,
    1,
    0xFFFFFFFF,
    0xfafbfbfd,
    0xf1f2f3f4,
    0x0a0b0c0d,
    0x01020304)

    adds w9, w0, #0xfff, lsl #12
TEST_END

TEST_BEGIN(ADDS_32S_ADDSUB_IMM, adds_x9_wsp_0FF_lsl12, 1)
TEST_INPUTS(0)
    adds w9, wsp, #0xfff, lsl #12
TEST_END

/* SUBS  <Xd>, <Xn|SP>, #<imm>{, <shift>} */
TEST_BEGIN(ADDS_64S_ADDSUB_IMM, adds_x9_sp_16, 1)
TEST_INPUTS(0)
    adds x9, sp, #16
TEST_END

TEST_BEGIN(ADDS_64S_ADDSUB_IMM, adds_x9_sp_16_lsl12, 1)
TEST_INPUTS(0)
    adds x9, sp, #16, lsl #12
TEST_END

TEST_BEGIN(ADDS_64S_ADDSUB_IMM, adds_x9_x0_1, 1)
TEST_INPUTS(
    0,
    1,
    0xFFFFFFFF,
    0xfafbfbfd,
    0xf1f2f3f4,
    0x0a0b0c0d,
    0x01020304,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFF00000000,
    0xfafbfbfdf1f2f3f4,
    0xf1f2f3f4fafbfbfd)

    adds x9, x0, #0x1
TEST_END

TEST_BEGIN(ADDS_64S_ADDSUB_IMM, adds_x9_x0_fff, 1)
TEST_INPUTS(
    0,
    1,
    0xFFFFFFFF,
    0xfafbfbfd,
    0xf1f2f3f4,
    0x0a0b0c0d,
    0x01020304,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFF00000000,
    0xfafbfbfdf1f2f3f4,
    0xf1f2f3f4fafbfbfd)

    adds x9, x0, #0xfff
TEST_END

TEST_BEGIN(ADDS_64S_ADDSUB_IMM, adds_x9_x0_0FF_lsl12, 1)
TEST_INPUTS(
    0,
    1,
    0xFFFFFFFF,
    0xfafbfbfd,
    0xf1f2f3f4,
    0x0a0b0c0d,
    0x01020304,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFF00000000,
    0xfafbfbfdf1f2f3f4,
    0xf1f2f3f4fafbfbfd)

    adds x9, x0, #0xfff, lsl #12
TEST_END

