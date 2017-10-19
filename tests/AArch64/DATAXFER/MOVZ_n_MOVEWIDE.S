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

TEST_BEGIN(MOVZ_32_MOVEWIDE, movz_w0_0x7000_lsl0, 1)
TEST_INPUTS(0x1122334455667788)
    movz ARG1_32, #0xabcd, lsl #0
TEST_END

TEST_BEGIN(MOVZ_32_MOVEWIDE, movz_w0_0x7000_lsl16, 1)
TEST_INPUTS(0x1122334455667788)
    movz ARG1_32, #0xabcd, lsl #16
TEST_END

TEST_BEGIN(MOVZ_64_MOVEWIDE, movz_x0_0x7000_lsl0, 1)
TEST_INPUTS(0x1122334455667788)
    movz ARG1_64, #0xabcd, lsl #0
TEST_END

TEST_BEGIN(MOVZ_64_MOVEWIDE, movz_x0_0x7000_lsl16, 1)
TEST_INPUTS(0x1122334455667788)
    movz ARG1_64, #0xabcd, lsl #16
TEST_END

TEST_BEGIN(MOVZ_64_MOVEWIDE, movz_x0_0x7000_lsl32, 1)
TEST_INPUTS(0x1122334455667788)
    movz ARG1_64, #0xabcd, lsl #32
TEST_END

TEST_BEGIN(MOVZ_64_MOVEWIDE, movz_x0_0x7000_lsl48, 1)
TEST_INPUTS(0x1122334455667788)
    movz ARG1_64, #0xabcd, lsl #48
TEST_END
