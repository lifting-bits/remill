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

/* LDP  <Wt1>, <Wt2>, [<Xn|SP>{, #<imm>}] */
TEST_BEGIN(LDP_32_LDSTPAIR_OFF, ldp_w0_w1_m64_off, 1)
TEST_INPUTS(0)

    add x3, sp, #-256
    ldp w4, w5, [x3, #0]
    ldp w6, w7, [x3, #32]
    ldp w8, w9, [x3, #64]
TEST_END

TEST_BEGIN(LDP_32_LDSTPAIR_OFF, ldp_w3_w5_m64_off_nowb, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldp w3, w5, [x3, #0]
TEST_END

TEST_BEGIN(LDP_32_LDSTPAIR_OFF, ldp_w4_w3_m64_off_nowb, 1)
TEST_INPUTS(0)

    add x3, sp, #-256
    ldp w4, w3, [x3, #0]
TEST_END

/* LDP  <Xt1>, <Xt2>, [<Xn|SP>{, #<imm>}] */
TEST_BEGIN(LDP_64_LDSTPAIR_OFF, ldp_x0_x1_m128_off, 1)
TEST_INPUTS(0)

    add x3, sp, #-256
    ldp x4, x5, [x3, #0]
    ldp x6, x7, [x3, #32]
    ldp x8, x9, [x3, #64]
TEST_END

/* LDP  <St1>, <St2>, [<Xn|SP>{, #<imm>}] */
TEST_BEGIN(LDP_S_LDSTPAIR_OFF, ldp_s0_s1_m64_off, 1)
TEST_INPUTS(0)

    add x3, sp, #-256
    ldp s0, s1, [x3, #0]
    ldp s2, s3, [x3, #32]
    ldp s4, s5, [x3, #64]
TEST_END

/* LDP  <Dt1>, <Dt2>, [<Xn|SP>{, #<imm>}] */
TEST_BEGIN(LDP_D_LDSTPAIR_OFF, ldp_d0_d1_m128_off, 1)
TEST_INPUTS(0)

    add x3, sp, #-256
    ldp d0, d1, [x3, #0]
    ldp d2, d3, [x3, #32]
    ldp d4, d5, [x3, #64]
TEST_END

/* LDP  <Qt1>, <Qt2>, [<Xn|SP>{, #<imm>}] */
TEST_BEGIN(LDP_Q_LDSTPAIR_OFF, ldp_q0_q1_m256_off, 1)
TEST_INPUTS(0)

    add x3, sp, #-256
    ldp q0, q1, [x3, #0]
    ldp q2, q3, [x3, #32]
    ldp q4, q5, [x3, #64]
TEST_END
