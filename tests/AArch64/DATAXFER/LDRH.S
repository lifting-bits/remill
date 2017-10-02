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

/* LDRH  <Wt>, [<Xn|SP>{, #<pimm>}] */
TEST_BEGIN(LDRH_32_LDST_POS, ldrh_w563_m16, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldrh w5, [x3]
    ldrh w6, [x3, #16]
    ldrh w3, [x3, #32]
TEST_END

/* LDRH  <Wt>, [<Xn|SP>], #<simm> */
TEST_BEGIN(LDRH_32_LDST_IMMPOST, ldrh_w56_m16_post, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldrh w5, [x3], #0
    ldrh w6, [x3], #32
TEST_END

TEST_BEGIN(LDRH_32_LDST_IMMPOST, ldrh_wzr_m16_post_alias, 1)
TEST_INPUTS(0)
    add sp, sp, #-256
    ldrh wzr, [sp], #16
TEST_END

/* LDRH  <Wt>, [<Xn|SP>, #<simm>]! */
TEST_BEGIN(LDRH_32_LDST_IMMPRE, ldrh_w5_m16_pre, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldrh w5, [x3, #16]!
TEST_END

/* LDRH  <Wt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}] */
TEST_BEGIN(LDRH_32_LDST_REGOFF, ldrh_w567_m16_off_w0_uxtw01, 1)
TEST_INPUTS(
    0,
    8)
    add x3, sp, #-256
    ldrh w5, [x3, ARG1_32, uxtw]
    ldrh w6, [x3, ARG1_32, uxtw #0]
    ldrh w7, [x3, ARG1_32, uxtw #1]
TEST_END

TEST_BEGIN(LDRH_32_LDST_REGOFF, ldrh_w567_m16_off_w0_sxtw01, 1)
TEST_INPUTS(
    0,
    0xfffffff8)  /* -8 */
    add x3, sp, #-256
    ldrh w5, [x3, ARG1_32, sxtw]
    ldrh w6, [x3, ARG1_32, sxtw #0]
    ldrh w7, [x3, ARG1_32, sxtw #1]
TEST_END

/* LDRH  <Wt>, [<Xn|SP>, <Xm>{, LSL <amount>}] */
TEST_BEGIN(LDRH_32_LDST_REGOFF, ldrh_w567_m16_off_w0_lsl01, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldrh w5, [x3, ARG1_64]  /* Implicit LSL 0 */
    ldrh w6, [x3, ARG1_64, lsl #0]  /* Explicit LSL 0 */
    ldrh w7, [x3, ARG1_64, lsl #1]  /* Explicit LSL 1 */
TEST_END
