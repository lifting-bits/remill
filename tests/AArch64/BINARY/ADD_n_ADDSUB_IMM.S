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

/* ADD  <Wd|WSP>, <Wn|WSP>, #<imm>{, <shift>} */
TEST_BEGIN(ADD_32_ADDSUB_IMM, add_w9_w0_0, 1)
TEST_INPUTS(
    0,
    1,
    0xFFFFFFFF,
    0xfafbfbfd,
    0xf1f2f3f4,
    0x0a0b0c0d,
    0x01020304)

    add w9, w0, #0
TEST_END

TEST_BEGIN(ADD_32_ADDSUB_IMM, add_w9_w0_0_lsl12, 1)
TEST_INPUTS(
    0,
    1,
    0xFFFFFFFF,
    0xfafbfbfd,
    0xf1f2f3f4,
    0x0a0b0c0d,
    0x01020304)

    add w9, w0, #0, lsl #12
TEST_END
