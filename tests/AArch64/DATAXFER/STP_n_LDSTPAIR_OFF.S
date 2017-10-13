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

/* STP  <Wt1>, <Wt2>, [<Xn|SP>{, #<imm>}] */
TEST_BEGIN(STP_32_LDSTPAIR_OFF, stp_w0_w1_m64_off, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0x41414141, 0xabababab)

    add x3, sp, #-256
    stp ARG1_32, ARG1_32, [x3, #0]
    stp ARG2_32, ARG2_32, [x3, #32]
    stp ARG1_32, ARG2_32, [x3, #64]
TEST_END

/* STP  <Xt1>, <Xt2>, [<Xn|SP>{, #<imm>}] */
TEST_BEGIN(STP_64_LDSTPAIR_OFF, stp_x0_x1_m128_off, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0x4141414156565656, 0xababababefefefef)

    add x3, sp, #-256
    stp ARG1_64, ARG1_64, [x3, #0]
    stp ARG2_64, ARG2_64, [x3, #32]
    stp ARG1_64, ARG2_64, [x3, #64]
TEST_END

/* STP  <St1>, <St2>, [<Xn|SP>{, #<imm>}] */
TEST_BEGIN(STP_S_LDSTPAIR_OFF, stp_s0_s1_m64_off, 1)
TEST_INPUTS(0)

    add x3, sp, #-256
    stp s0, s1, [x3, #0]
    stp s2, s3, [x3, #32]
    stp s4, s5, [x3, #64]
TEST_END

/* STP  <Dt1>, <Dt2>, [<Xn|SP>{, #<imm>}] */
TEST_BEGIN(STP_D_LDSTPAIR_OFF, stp_d0_d1_m128_off, 1)
TEST_INPUTS(0)

    add x3, sp, #-256
    stp d0, d1, [x3, #0]
    stp d2, d3, [x3, #32]
    stp d4, d5, [x3, #64]
TEST_END

// MvW type isnt supported
// remill/remill/Arch/Runtime/Operators.h:437:1: error: static_assert failed "Invalid value size for MVnW."
// MAKE_MWRITEV(U, 128, dqwords, 128, uint128_t)

/* STP  <Qt1>, <Qt2>, [<Xn|SP>{, #<imm>}] */
// TEST_BEGIN(STP_Q_LDSTPAIR_OFF, stp_q0_q1_m256_off, 1)
// TEST_INPUTS(0)

//     add x3, sp, #-256
//     stp q0, q1, [x3, #0]
//     stp q2, q3, [x3, #32]
//     stp q4, q5, [x3, #64]
// TEST_END
