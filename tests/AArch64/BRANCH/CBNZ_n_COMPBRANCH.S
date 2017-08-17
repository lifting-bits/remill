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

TEST_BEGIN(CBNZ_32_COMPBRANCH, cbnz_w0, 1)
TEST_INPUTS(
    0,
    1,
    0x100000000,  /* w0 == 0, but x0 != 0 */
    0xffffffff)

  mov x9, #1
  cbnz w0, 99f
  mov x9, #0
99:
TEST_END

TEST_BEGIN(CBNZ_64_COMPBRANCH, cbnz_x0, 1)
TEST_INPUTS(
    0,
    1,
    0x100000000,  /* w0 == 0, but x0 != 0 */
    0xffffffff,
    0xffffffffffffffff)

  mov x9, #1
  cbnz x0, 99f
  mov x9, #0
99:
TEST_END

