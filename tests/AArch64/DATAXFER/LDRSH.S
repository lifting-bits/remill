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

/* LDRSH  <Wt>, [<Xn|SP>{, #<pimm>}] */
TEST_BEGIN(LDRSH_32_LDST_POS, ldrsh_w563_m16, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldrsh w5, [x3]
    ldrsh w6, [x3, #16]
    ldrsh w3, [x3, #32]
TEST_END

/* LDRSH  <Xt>, [<Xn|SP>{, #<pimm>}] */
TEST_BEGIN(LDRSH_64_LDST_POS, ldrsh_x563_m16, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldrsh x5, [x3]
    ldrsh x6, [x3, #16]
    ldrsh x3, [x3, #32]
TEST_END

/* LDRSH  <Wt>, [<Xn|SP>], #<simm> */
TEST_BEGIN(LDRSH_32_LDST_IMMPOST, ldrsh_w56_m16_post, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldrsh w5, [x3], #0
    ldrsh w6, [x3], #32
TEST_END

/* LDRSH  <Xt>, [<Xn|SP>], #<simm> */
TEST_BEGIN(LDRSH_64_LDST_IMMPOST, ldrsh_x56_m16_post, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldrsh x5, [x3], #0
    ldrsh x6, [x3], #32
TEST_END

TEST_BEGIN(LDRSH_32_LDST_IMMPOST, ldrsh_wzr_m16_post_alias, 1)
TEST_INPUTS(0)
    add sp, sp, #-256
    ldrsh wzr, [sp], #16
TEST_END

TEST_BEGIN(LDRSH_64_LDST_IMMPOST, ldrsh_xzr_m16_post_alias, 1)
TEST_INPUTS(0)
    add sp, sp, #-256
    ldrsh xzr, [sp], #16
TEST_END

/* LDRSH  <Wt>, [<Xn|SP>, #<simm>]! */
TEST_BEGIN(LDRSH_32_LDST_IMMPRE, ldrsh_w5_m16_pre, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldrsh w5, [x3, #16]!
TEST_END

/* LDRSH  <Xt>, [<Xn|SP>, #<simm>]! */
TEST_BEGIN(LDRSH_64_LDST_IMMPRE, ldrsh_x5_m16_pre, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldrsh x5, [x3, #16]!
TEST_END

/* LDRSH  <Wt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}] */
TEST_BEGIN(LDRSH_32_LDST_REGOFF, ldrsh_w567_m16_off_w0_uxtw, 1)
TEST_INPUTS(
    0,
    8)
    add x3, sp, #-256
    ldrsh w5, [x3, ARG1_32, uxtw]
    ldrsh w6, [x3, ARG1_32, uxtw #0]
    ldrsh w7, [x3, ARG1_32, uxtw #1]
TEST_END

/* LDRSH  <Xt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}] */
TEST_BEGIN(LDRSH_64_LDST_REGOFF, ldrsh_x567_m16_off_w0_uxtw, 1)
TEST_INPUTS(
    0,
    8)
    add x3, sp, #-256
    ldrsh x5, [x3, ARG1_32, uxtw]
    ldrsh x6, [x3, ARG1_32, uxtw #0]
    ldrsh x7, [x3, ARG1_32, uxtw #1]
TEST_END

TEST_BEGIN(LDRSH_32_LDST_REGOFF, ldrsh_w567_m16_off_w0_sxtw, 1)
TEST_INPUTS(
    0,
    0xfffffff8)  /* -8 */
    add x3, sp, #-256
    ldrsh w5, [x3, ARG1_32, sxtw]
    ldrsh w6, [x3, ARG1_32, sxtw #0]
    ldrsh w7, [x3, ARG1_32, sxtw #1]
TEST_END

TEST_BEGIN(LDRSH_64_LDST_REGOFF, ldrsh_x567_m16_off_w0_sxtw, 1)
TEST_INPUTS(
    0,
    0xfffffff8)  /* -8 */
    add x3, sp, #-256
    ldrsh x5, [x3, ARG1_32, sxtw]
    ldrsh x6, [x3, ARG1_32, sxtw #0]
    ldrsh x7, [x3, ARG1_32, sxtw #1]
TEST_END

/* LDRSH  <Wt>, [<Xn|SP>, <Xm>{, LSL <amount>}] */
TEST_BEGIN(LDRSH_32_LDST_REGOFF, ldrsh_w5_m16_off_w0, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldrsh w5, [x3, ARG1_64]  /* Implicit LSL 0 */
TEST_END

/* LDRSH  <Xt>, [<Xn|SP>, <Xm>{, LSL <amount>}] */
TEST_BEGIN(LDRSH_64_LDST_REGOFF, ldrsh_x5_m16_off_w0, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldrsh x5, [x3, ARG1_64]  /* Implicit LSL 0 */
TEST_END

TEST_BEGIN(LDRSH_32_LDST_REGOFF, ldrsh_w56_m16_off_w0_lsl01, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldrsh w5, [x3, ARG1_64, lsl #0]  /* Explicit LSL 0 */
    ldrsh w6, [x3, ARG1_64, lsl #1]  /* Explicit LSL 1 */
TEST_END

TEST_BEGIN(LDRSH_64_LDST_REGOFF, ldrsh_x56_m16_off_w0_lsl01, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldrsh x5, [x3, ARG1_64, lsl #0]  /* Explicit LSL 0 */
    ldrsh x6, [x3, ARG1_64, lsl #1]  /* Explicit LSL 1 */
TEST_END
