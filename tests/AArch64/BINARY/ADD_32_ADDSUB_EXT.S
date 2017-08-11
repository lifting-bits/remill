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

/* ADD  <Wd|WSP>, <Wn|WSP>, <Wm>{, <extend> {#<amount>}} */
TEST_BEGIN(ADD_32_ADDSUB_EXT, add_w9_w0_w1_uxtb0, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304)

    add w9, w0, w1, uxtb #0
TEST_END

TEST_BEGIN(ADD_32_ADDSUB_EXT, add_w9_w0_w1_uxtb3, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304)

    add w9, w0, w1, uxtb #3
TEST_END

TEST_BEGIN(ADD_32_ADDSUB_EXT, add_w9_w0_w1_sxtb0, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304)

    add w9, w0, w1, sxtb #0
TEST_END

TEST_BEGIN(ADD_32_ADDSUB_EXT, add_w9_w0_w1_sxtb3, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304)

    add w9, w0, w1, sxtb #3
TEST_END

TEST_BEGIN(ADD_32_ADDSUB_EXT, add_w9_w0_w1_uxth0, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304)

    add w9, w0, w1, uxth #0
TEST_END

TEST_BEGIN(ADD_32_ADDSUB_EXT, add_w9_w0_w1_uxth3, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304)

    add w9, w0, w1, uxth #3
TEST_END

TEST_BEGIN(ADD_32_ADDSUB_EXT, add_w9_w0_w1_sxth0, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304)

    add w9, w0, w1, sxth #0
TEST_END

TEST_BEGIN(ADD_32_ADDSUB_EXT, add_w9_w0_w1_sxth3, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304)

    add w9, w0, w1, sxth #3
TEST_END

TEST_BEGIN(ADD_32_ADDSUB_EXT, add_w9_w0_w1_uxtw0, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304)

    add w9, w0, w1, uxtw #0
TEST_END

TEST_BEGIN(ADD_32_ADDSUB_EXT, add_w9_w0_w1_uxtw3, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304)

    add w9, w0, w1, uxtw #3
TEST_END

TEST_BEGIN(ADD_32_ADDSUB_EXT, add_w9_w0_w1_sxtw0, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304)

    add w9, w0, w1, sxtw #0
TEST_END

TEST_BEGIN(ADD_32_ADDSUB_EXT, add_w9_w0_w1_sxtw3, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304)

    add w9, w0, w1, sxtw #3
TEST_END

TEST_BEGIN(ADD_32_ADDSUB_EXT, add_w9_w0_w1_uxtx0, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304)

    add w9, w0, w1, uxtx #0
TEST_END

TEST_BEGIN(ADD_32_ADDSUB_EXT, add_w9_w0_w1_uxtx3, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304)

    add w9, w0, w1, uxtx #3
TEST_END

TEST_BEGIN(ADD_32_ADDSUB_EXT, add_w9_w0_w1_sxtx0, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304)

    add w9, w0, w1, sxtx #0
TEST_END

TEST_BEGIN(ADD_32_ADDSUB_EXT, add_w9_w0_w1_sxtx3, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304)

    add w9, w0, w1, sxtx #3
TEST_END

