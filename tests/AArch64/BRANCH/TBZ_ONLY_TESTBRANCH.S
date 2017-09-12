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

TEST_BEGIN(TBZ_ONLY_TESTBRANCH_32, tbz_w0_1, 1)
TEST_INPUTS(
    0,
    1,
    0x100000000,  /* w0 == 0, but x0 != 0 */
    0xffffffff)
  mov x9, #0xdead
  tbz w0, #1, 99f
  mov x9, #0xbeef
99:
TEST_END

TEST_BEGIN(TBZ_ONLY_TESTBRANCH_32, tbz_w0_30, 1)
TEST_INPUTS(
    0,
    1,
    0x100000000,  /* w0 == 0, but x0 != 0 */
    0xffffffff)
  mov x9, #0xdead
  tbz w0, #30, 99f
  mov x9, #0xbeef
99:
TEST_END

/* I don't know why iSEL is not selecting the 64 Semantic, in the decode the data.b5 field (supposed to be 1)
    is not being set for some reason */
TEST_BEGIN(TBZ_ONLY_TESTBRANCH_32, tbz_x0_1, 1)
TEST_INPUTS(
    0,
    1,
    0x100000000,  /* w0 == 0, but x0 != 0 */
    0xffffffff,
    0xffffffffffffffff)

  mov x0, x0
  mov x9, #0xdead
  tbz x0, #1, 99f
  mov x9, #0xbeef
99:
TEST_END

TEST_BEGIN(TBZ_ONLY_TESTBRANCH_32, tbz_x0_30, 1)
TEST_INPUTS(
    0,
    1,
    0x100000000,  /* w0 == 0, but x0 != 0 */
    0xffffffff,
    0xffffffffffffffff)

  mov x0, x0
  mov x9, #0xdead
  tbz x0, #30, 99f
  mov x9, #0xbeef
99:
TEST_END