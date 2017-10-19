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
 * dildributed under the License is dildributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

TEST_BEGIN(STR_32_LDST_REGOFF, str_w567_m32_uxtw, 1)
TEST_INPUTS(0, 8)
    add x3, sp, #-256
    str w5, [x3, ARG1_32, uxtw]
    str w6, [x3, ARG1_32, uxtw #0]
    str w7, [x3, ARG1_32, uxtw #2]
TEST_END

TEST_BEGIN(STR_32_LDST_REGOFF, str_w567_m32_sxtw, 1)
TEST_INPUTS(
    0,
    8,
    0xfffffffffffffff8,
    0xfffffffffffffff0)

    add x3, sp, #-256
    str w5, [x3, ARG1_32, sxtw]
    str w6, [x3, ARG1_32, sxtw #0]
    str w7, [x3, ARG1_32, sxtw #2]
TEST_END

TEST_BEGIN(STR_32_LDST_REGOFF, str_w567_m32_lsl, 1)
TEST_INPUTS(0, 8)
    add x3, sp, #-256
    str w6, [x3, ARG1_64, lsl #0]
    str w7, [x3, ARG1_64, lsl #2]
TEST_END

TEST_BEGIN(STR_64_LDST_REGOFF, str_x567_m64_uxtw, 1)
TEST_INPUTS(0, 8)
    add x3, sp, #-256
    str x5, [x3, ARG1_32, uxtw]
    str x6, [x3, ARG1_32, uxtw #0]
    str x7, [x3, ARG1_32, uxtw #3]
TEST_END

TEST_BEGIN(STR_64_LDST_REGOFF, str_x567_m64_sxtx, 1)
TEST_INPUTS(
    0,
    8,
    0xfffffffffffffff8,
    0xfffffffffffffff0)

    add x3, sp, #-256
    str x5, [x3, ARG1_64, sxtx]
    str x6, [x3, ARG1_64, sxtx #0]
    str x7, [x3, ARG1_64, sxtx #3]
TEST_END

TEST_BEGIN(STR_64_LDST_REGOFF, str_x567_m64_lsl, 1)
TEST_INPUTS(0, 8)
    add x3, sp, #-256
    str x6, [x3, ARG1_64, lsl #0]
    str x7, [x3, ARG1_64, lsl #3]
TEST_END

TEST_BEGIN(STR_Q_LDST_REGOFF, str_10_m128_uxt, 1)
TEST_INPUTS(
    0,
    8)
    add x3, sp, #-256

    str q2, [x3, ARG1_32, uxtw]
    str q3, [x3, ARG1_32, uxtw #0]
    str q4, [x3, ARG1_32, uxtw #4]

TEST_END

TEST_BEGIN(STR_Q_LDST_REGOFF, str_q0_m128_sxt, 1)
TEST_INPUTS(
    0,
    8,
    0xfffffffffffffff8,
    0xfffffffffffffff0)
    add x3, sp, #-256

    str q2, [x3, ARG1_32, sxtw]
    str q3, [x3, ARG1_32, sxtw #0]
    str q4, [x3, ARG1_32, sxtw #4]

    str q5, [x3, ARG1_64, sxtx]
    str q6, [x3, ARG1_64, sxtx #0]
    str q7, [x3, ARG1_64, sxtx #4]
TEST_END

TEST_BEGIN(STR_Q_LDST_REGOFF, str_q0_m128_lsl, 1)
TEST_INPUTS(
    0,
    8)
    add x3, sp, #-256

    str q0, [x3, ARG1_64, lsl #0]
    str q1, [x3, ARG1_64, lsl #4]
TEST_END
