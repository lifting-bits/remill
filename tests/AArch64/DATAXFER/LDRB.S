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

/* LDRB  <Wt>, [<Xn|SP>{, #<pimm>}] */
TEST_BEGIN(LDRB_32_LDST_POS, ldrb_w563_m8, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldrb w5, [x3]
    ldrb w6, [x3, #16]
    ldrb w3, [x3, #32]
TEST_END

/* LDRB  <Wt>, [<Xn|SP>], #<simm> */
TEST_BEGIN(LDRB_32_LDST_IMMPOST, ldrb_w56_m8_post, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldrb w5, [x3], #0
    ldrb w6, [x3], #32
TEST_END

/*
TEST_BEGIN(LDRB_32_LDST_IMMPOST, ldrb_w3_m8_post_alias, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    .byte 0x63, 0x04, 0x41, 0x38  // ldrb w3, [x3], #16
TEST_END

*/

TEST_BEGIN(LDRB_32_LDST_IMMPOST, ldrb_wzr_m8_post_alias, 1)
TEST_INPUTS(0)
    add sp, sp, #-256
    ldrb wzr, [sp], #16
TEST_END


/* LDRB  <Wt>, [<Xn|SP>, #<simm>]! */
TEST_BEGIN(LDRB_32_LDST_IMMPRE, ldrb_w5_m8_pre, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldrb w5, [x3, #16]!
TEST_END

/*
TEST_BEGIN(LDRB_32_LDST_IMMPRE, ldrb_w3_m8_pre_alias, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    .byte 0x63, 0x0c, 0x41, 0x38  // ldrb w3, [x3, #16]!
TEST_END
*/

/* LDRB  <Wt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}] */
TEST_BEGIN(LDRB_32B_LDST_REGOFF, ldrb_w56_m8_off_w0_uxtw0, 1)
TEST_INPUTS(
    0,
    8)
    add x3, sp, #-256
    ldrb w5, [x3, ARG1_32, uxtw]
    ldrb w6, [x3, ARG1_32, uxtw #0]
TEST_END

TEST_BEGIN(LDRB_32B_LDST_REGOFF, ldrb_w67_m8_off_w0_sxtw0, 1)
TEST_INPUTS(
    0,
    0xfffffff8)  /* -8 */
    add x3, sp, #-256
    ldrb w6, [x3, ARG1_32, sxtw]
    ldrb w7, [x3, ARG1_32, sxtw #0]
TEST_END

/* LDRB  <Wt>, [<Xn|SP>, <Xm>{, LSL <amount>}] */
TEST_BEGIN(LDRB_32BL_LDST_REGOFF, ldrb_w5_m8_off_w0_lsl0, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldrb w5, [x3, ARG1_64]  /* Implicit LSL 0 */
    ldrb w5, [x3, ARG1_64, lsl #0]  /* Explicit LSL 0 */
TEST_END
