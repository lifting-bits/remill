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

TEST_BEGIN(LDR_32_LDST_REGOFF, ldr_w5_m32_uxt, 1)
TEST_INPUTS(
    0,
    8)
    add x3, sp, #-256

    ldr w7, [x3, ARG1_32, uxtw]
    ldr w8, [x3, ARG1_32, uxtw #0]
    ldr w9, [x3, ARG1_32, uxtw #2]
TEST_END

TEST_BEGIN(LDR_32_LDST_REGOFF, ldr_w5_m32_regoff_sxt, 1)
TEST_INPUTS(
    0,
    8,
    0xfffffffffffffff8,
    0xfffffffffffffff0)

    add x3, sp, #-256

    ldr w5, [x3, ARG1_64, sxtx]
    ldr w6, [x3, ARG1_64, sxtx #0]
    ldr w7, [x3, ARG1_64, sxtx #2]

    ldr w10, [x3, ARG1_32, sxtw]
    ldr w11, [x3, ARG1_32, sxtw #0]
    ldr w12, [x3, ARG1_32, sxtw #2]
TEST_END

TEST_BEGIN(LDR_32_LDST_REGOFF, ldr_w5_m32_lsl, 1)
TEST_INPUTS(
    0,
    8,
    0xffffffffffffffff)
    add x3, sp, #-256
    ldr w9, [x3, ARG1_64, lsl #0]
    ldr w10, [x3, ARG1_64, lsl #2]
TEST_END

// ------------------------------------

TEST_BEGIN(LDR_64_LDST_REGOFF, ldr_x5_m64_uxt, 1)
TEST_INPUTS(
    0,
    8)
    add x3, sp, #-256

    ldr x7, [x3, ARG1_32, uxtw]
    ldr x8, [x3, ARG1_32, uxtw #0]
    ldr x9, [x3, ARG1_32, uxtw #3]
TEST_END

TEST_BEGIN(LDR_64_LDST_REGOFF, ldr_x5_m64_regoff_lsl, 1)
TEST_INPUTS(
    0,
    8,
    0xffffffffffffffff)
    add x3, sp, #-256

    ldr x10, [x3, ARG1_64, lsl #0]
    ldr x10, [x3, ARG1_64, lsl #3]
TEST_END

TEST_BEGIN(LDR_64_LDST_REGOFF, ldr_x5_m64_regoff_sxt, 1)
TEST_INPUTS(
    0,
    8,
    0xfffffffffffffff8,
    0xfffffffffffffff0)
    add x3, sp, #-256

    ldr x5, [x3, ARG1_64, sxtx]
    ldr x6, [x3, ARG1_64, sxtx #0]
    ldr x7, [x3, ARG1_64, sxtx #3]

    ldr x10, [x3, ARG1_32, sxtw]
    ldr x11, [x3, ARG1_32, sxtw #0]
    ldr x12, [x3, ARG1_32, sxtw #3]
TEST_END

// ------------------------------------

TEST_BEGIN(LDR_B_LDST_REGOFF, ldr_b0_m8_uxt, 1)
TEST_INPUTS(
    0,
    8)
    add x3, sp, #-256

    ldr b2, [x3, ARG1_32, uxtw]
    ldr b3, [x3, ARG1_32, uxtw #0]
TEST_END

TEST_BEGIN(LDR_B_LDST_REGOFF, ldr_b0_m8_sxt, 1)
TEST_INPUTS(
    0,
    8,
    0xfffffffffffffff8,
    0xfffffffffffffff0)
    add x3, sp, #-256

    ldr b2, [x3, ARG1_32, sxtw]
    ldr b3, [x3, ARG1_32, sxtw #0]

    ldr b4, [x3, ARG1_64, sxtx]
    ldr b5, [x3, ARG1_64, sxtx #0]
TEST_END

TEST_BEGIN(LDR_BL_LDST_REGOFF, ldr_b0_m8_implicit_lsl0, 1)
TEST_INPUTS(
    0,
    8)
    add x3, sp, #-256

    ldr b0, [x3, ARG1_64]
TEST_END

TEST_BEGIN(LDR_BL_LDST_REGOFF, ldr_b0_m8_explicit_lsl0, 1)
TEST_INPUTS(
    0,
    8)
    add x3, sp, #-256

    ldr b2, [x3, ARG1_64, lsl #0]
TEST_END

// ------------------------------------

TEST_BEGIN(LDR_H_LDST_REGOFF, ldr_h0_m16_uxt, 1)
TEST_INPUTS(
    0,
    8)
    add x3, sp, #-256

    ldr h2, [x3, ARG1_32, uxtw]
    ldr h3, [x3, ARG1_32, uxtw #0]
    ldr h4, [x3, ARG1_32, uxtw #1]
TEST_END

TEST_BEGIN(LDR_H_LDST_REGOFF, ldr_h0_m16_sxt, 1)
TEST_INPUTS(
    0,
    8,
    0xfffffffffffffff8,
    0xfffffffffffffff0)
    add x3, sp, #-256

    ldr h2, [x3, ARG1_32, sxtw]
    ldr h3, [x3, ARG1_32, sxtw #0]
    ldr h4, [x3, ARG1_32, sxtw #1]

    ldr h5, [x3, ARG1_64, sxtx]
    ldr h6, [x3, ARG1_64, sxtx #0]
    ldr h7, [x3, ARG1_64, sxtx #1]
TEST_END

TEST_BEGIN(LDR_H_LDST_REGOFF, ldr_h0_m16_lsl, 1)
TEST_INPUTS(
    0,
    8)
    add x3, sp, #-256

    ldr h0, [x3, ARG1_64, lsl #0]
    ldr h1, [x3, ARG1_64, lsl #1]
TEST_END

// ------------------------------------

TEST_BEGIN(LDR_S_LDST_REGOFF, ldr_s0_m32_uxt, 1)
TEST_INPUTS(
    0,
    8)
    add x3, sp, #-256

    ldr s2, [x3, ARG1_32, uxtw]
    ldr s3, [x3, ARG1_32, uxtw #0]
    ldr s4, [x3, ARG1_32, uxtw #2]
TEST_END

TEST_BEGIN(LDR_S_LDST_REGOFF, ldr_s0_m32_sxt, 1)
TEST_INPUTS(
    0,
    8,
    0xfffffffffffffff8,
    0xfffffffffffffff0)
    add x3, sp, #-256

    ldr s2, [x3, ARG1_32, sxtw]
    ldr s3, [x3, ARG1_32, sxtw #0]
    ldr s4, [x3, ARG1_32, sxtw #2]

    ldr s5, [x3, ARG1_64, sxtx]
    ldr s6, [x3, ARG1_64, sxtx #0]
    ldr s7, [x3, ARG1_64, sxtx #2]
TEST_END

TEST_BEGIN(LDR_S_LDST_REGOFF, ldr_s0_m32_lsl, 1)
TEST_INPUTS(
    0,
    8)
    add x3, sp, #-256

    ldr s0, [x3, ARG1_64, lsl #0]
    ldr s1, [x3, ARG1_64, lsl #2]
TEST_END

// ------------------------------------

TEST_BEGIN(LDR_D_LDST_REGOFF, ldr_d0_m64_uxt, 1)
TEST_INPUTS(
    0,
    8)
    add x3, sp, #-256

    ldr d2, [x3, ARG1_32, uxtw]
    ldr d3, [x3, ARG1_32, uxtw #0]
    ldr d4, [x3, ARG1_32, uxtw #3]
TEST_END

TEST_BEGIN(LDR_D_LDST_REGOFF, ldr_d0_m64_sxt, 1)
TEST_INPUTS(
    0,
    8,
    0xfffffffffffffff8,
    0xfffffffffffffff0)
    add x3, sp, #-256

    ldr d2, [x3, ARG1_32, sxtw]
    ldr d3, [x3, ARG1_32, sxtw #0]
    ldr d4, [x3, ARG1_32, sxtw #3]

    ldr d5, [x3, ARG1_64, sxtx]
    ldr d6, [x3, ARG1_64, sxtx #0]
    ldr d7, [x3, ARG1_64, sxtx #3]
TEST_END

TEST_BEGIN(LDR_D_LDST_REGOFF, ldr_d0_m64_lsl, 1)
TEST_INPUTS(
    0,
    8)
    add x3, sp, #-256

    ldr d0, [x3, ARG1_64, lsl #0]
    ldr d1, [x3, ARG1_64, lsl #3]
TEST_END

// ------------------------------------

TEST_BEGIN(LDR_Q_LDST_REGOFF, ldr_10_m128_uxt, 1)
TEST_INPUTS(
    0,
    8)
    add x3, sp, #-256

    ldr q2, [x3, ARG1_32, uxtw]
    ldr q3, [x3, ARG1_32, uxtw #0]
    ldr q4, [x3, ARG1_32, uxtw #4]

TEST_END

TEST_BEGIN(LDR_Q_LDST_REGOFF, ldr_q0_m128_sxt, 1)
TEST_INPUTS(
    0,
    8,
    0xfffffffffffffff8,
    0xfffffffffffffff0)
    add x3, sp, #-256

    ldr q2, [x3, ARG1_32, sxtw]
    ldr q3, [x3, ARG1_32, sxtw #0]
    ldr q4, [x3, ARG1_32, sxtw #4]

    ldr q5, [x3, ARG1_64, sxtx]
    ldr q6, [x3, ARG1_64, sxtx #0]
    ldr q7, [x3, ARG1_64, sxtx #4]
TEST_END

TEST_BEGIN(LDR_Q_LDST_REGOFF, ldr_q0_m128_lsl, 1)
TEST_INPUTS(
    0,
    8)
    add x3, sp, #-256

    ldr q0, [x3, ARG1_64, lsl #0]
    ldr q1, [x3, ARG1_64, lsl #4]
TEST_END
