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

/* LDRSB  <Wt>, [<Xn|SP>{, #<pimm>}] */
TEST_BEGIN(LDRSB_32_LDST_POS, ldrsb_w563_m8, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldrsb w5, [x3]
    ldrsb w6, [x3, #16]
    ldrsb w3, [x3, #32]
TEST_END

/* LDRSB  <Xt>, [<Xn|SP>{, #<pimm>}] */
TEST_BEGIN(LDRSB_64_LDST_POS, ldrsb_x563_m8, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldrsb x5, [x3]
    ldrsb x6, [x3, #16]
    ldrsb x3, [x3, #32]
TEST_END

/* LDRSB  <Wt>, [<Xn|SP>], #<simm> */
TEST_BEGIN(LDRSB_32_LDST_IMMPOST, ldrsb_w56_m8_post, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldrsb w5, [x3], #0
    ldrsb w6, [x3], #32
TEST_END

/* LDRSB  <Xt>, [<Xn|SP>], #<simm> */
TEST_BEGIN(LDRSB_64_LDST_IMMPOST, ldrsb_x56_m8_post, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldrsb x5, [x3], #0
    ldrsb x6, [x3], #32
TEST_END

TEST_BEGIN(LDRSB_32_LDST_IMMPOST, ldrsb_wzr_m8_post_alias, 1)
TEST_INPUTS(0)
    add sp, sp, #-256
    ldrsb wzr, [sp], #16
TEST_END

TEST_BEGIN(LDRSB_64_LDST_IMMPOST, ldrsb_xzr_m8_post_alias, 1)
TEST_INPUTS(0)
    add sp, sp, #-256
    ldrsb xzr, [sp], #16
TEST_END

/* LDRSB  <Wt>, [<Xn|SP>, #<simm>]! */
TEST_BEGIN(LDRSB_32_LDST_IMMPRE, ldrsb_w5_m8_pre, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldrsb w5, [x3, #16]!
TEST_END

/* LDRSB  <Xt>, [<Xn|SP>, #<simm>]! */
TEST_BEGIN(LDRSB_64_LDST_IMMPRE, ldrsb_x5_m8_pre, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldrsb x5, [x3, #16]!
TEST_END

/* LDRSB  <Wt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}] */
TEST_BEGIN(LDRSB_32B_LDST_REGOFF, ldrsb_w56_m8_off_w0_uxtw, 1)
TEST_INPUTS(
    0,
    8)
    add x3, sp, #-256
    ldrsb w5, [x3, ARG1_32, uxtw]
    ldrsb w6, [x3, ARG1_32, uxtw #0]
TEST_END

/* LDRSB  <Xt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}] */
TEST_BEGIN(LDRSB_64B_LDST_REGOFF, ldrsb_x56_m8_off_w0_uxtw, 1)
TEST_INPUTS(
    0,
    8)
    add x3, sp, #-256
    ldrsb x5, [x3, ARG1_32, uxtw]
    ldrsb x6, [x3, ARG1_32, uxtw #0]
TEST_END

TEST_BEGIN(LDRSB_32B_LDST_REGOFF, ldrsb_w67_m8_off_w0_sxtw, 1)
TEST_INPUTS(
    0,
    0xfffffff8)  /* -8 */
    add x3, sp, #-256
    ldrsb w6, [x3, ARG1_32, sxtw]
    ldrsb w7, [x3, ARG1_32, sxtw #0]
TEST_END

TEST_BEGIN(LDRSB_64B_LDST_REGOFF, ldrsb_x67_m8_off_w0_sxtw, 1)
TEST_INPUTS(
    0,
    0xfffffff8)  /* -8 */
    add x3, sp, #-256
    ldrsb x6, [x3, ARG1_32, sxtw]
    ldrsb x7, [x3, ARG1_32, sxtw #0]
TEST_END

/* LDRSB  <Wt>, [<Xn|SP>, <Xm>{, LSL <amount>}] */
TEST_BEGIN(LDRSB_32BL_LDST_REGOFF, ldrsb_w56_m8_off_w0_lsl0, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldrsb w5, [x3, ARG1_64]  /* Implicit LSL 0 */
    ldrsb w6, [x3, ARG1_64, lsl #0]  /* Explicit LSL 0 */
TEST_END

TEST_BEGIN(LDRSB_64BL_LDST_REGOFF, ldrsb_x56_m8_off_w0_lsl0, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldrsb x5, [x3, ARG1_64]  /* Implicit LSL 0 */
    ldrsb x6, [x3, ARG1_64, lsl #0]  /* Explicit LSL 0 */
TEST_END

