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

/* REV16  <Wd>, <Wn> */
TEST_BEGIN(REV16_32_DP_1SRC, rev16_w3_w0, 1)
TEST_INPUTS(0xaabbccddeeff1122)
    rev16 w3, ARG1_32
TEST_END

/* REV16  <Xd>, <Xn> */
TEST_BEGIN(REV16_64_DP_1SRC, rev16_x3_x0, 1)
TEST_INPUTS(0xaabbccddeeff1122)
    rev16 x3, ARG1_64
TEST_END

/* REV  <Wd>, <Wn> */
TEST_BEGIN(REV_32_DP_1SRC, rev_w3_w0, 1)
TEST_INPUTS(0xaabbccddeeff1122)
    rev w3, ARG1_32
TEST_END

/* REV32  <Xd>, <Xn> */
TEST_BEGIN(REV32_64_DP_1SRC, rev32_x3_x0, 1)
TEST_INPUTS(0xaabbccddeeff1122)
    rev32 x3, ARG1_64
TEST_END

/* REV  <Xd>, <Xn> */
TEST_BEGIN(REV_64_DP_1SRC, rev_x3_x0, 1)
TEST_INPUTS(0xaabbccddeeff1122)
    rev x3, ARG1_64
TEST_END
