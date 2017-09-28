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

/* STRB  <Wt>, [<Xn|SP>{, #<pimm>}] */
TEST_BEGIN(STRB_32_LDST_POS, strb_w563_m8, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldp w5, w6, [x3]
    strb w5, [x3, #16]
    strb w6, [x3, #32]
TEST_END

/* STRB  <Wt>, [<Xn|SP>], #<simm> */
TEST_BEGIN(STRB_32_LDST_IMMPOST, strb_w5_m8_post, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldp w5, w6, [x3]
    strb w5, [x3], #16
    strb w6, [x3], #32
TEST_END

TEST_BEGIN(STRB_32_LDST_IMMPOST, strb_wzr_m8_post_alias, 1)
TEST_INPUTS(0)
    add sp, sp, #-256
    strb wzr, [sp], #16
TEST_END


/* STRB  <Wt>, [<Xn|SP>, #<simm>]! */
TEST_BEGIN(STRB_32_LDST_IMMPRE, strb_w5_m8_pre, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldr w5, [x3]
    strb w5, [x3, #16]!
TEST_END

/* STRB  <Wt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}] */
TEST_BEGIN(STRB_32B_LDST_REGOFF, strb_w5_m8_off_w0_uxtw, 1)
TEST_INPUTS(
    0,
    8,
    16,
    32)
    add x3, sp, #-256
    ldp w5, w6, [x3]
    strb w5, [x3, ARG1_32, uxtw]
    strb w6, [x3, ARG1_32, uxtw #0]
TEST_END

TEST_BEGIN(STRB_32B_LDST_REGOFF, strb_w5_m8_off_w0_sxtw, 1)
TEST_INPUTS(
    0,
    0xfffffff8,  /* -8 */
    0xfffffff0,  /* -16 */
    0xffffffe0)  /* -32 */
    add x3, sp, #-256
    ldp w5, w6, [x3]
    strb w6, [x3, ARG1_32, sxtw]
    strb w7, [x3, ARG1_32, sxtw #0]
TEST_END

/* STRB  <Wt>, [<Xn|SP>, <Xm>{, LSL <amount>}] */
TEST_BEGIN(STRB_32BL_LDST_REGOFF, strb_w5_m8_off_w0, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldr w5, [x3, #16]
    strb w5, [x3, ARG1_64]  /* Implicit LSL 0 */
TEST_END

TEST_BEGIN(STRB_32BL_LDST_REGOFF, strb_w5_m8_off_w0_lsl0, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldr w5, [x3, #16]
    strb w5, [x3, ARG1_64, lsl #0]  /* Explicit LSL 0 */
TEST_END
