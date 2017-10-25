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


/* RBIT  <Wd>, <Wn> */
TEST_BEGIN(RBIT_32_DP_1SRC, rbit_w3_w0, 1)
TEST_INPUTS(0xaabbccddeeff1122)
    rbit w3, ARG1_32
TEST_END


/* RBIT  <Xd>, <Xn> */
TEST_BEGIN(RBIT_64_DP_1SRC, rbit_x3_x0, 1)
TEST_INPUTS(0xaabbccddeeff1122)
    rbit x3, ARG1_64
TEST_END
