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

/* STRH  <Wt>, [<Xn|SP>{, #<pimm>}] */
// Breaks with 
// F1004 21:33:34.664389  1004 Util.cpp:272] Error writing module to file tests_aarch64.bc: Incorrect number of arguments passed to called function!
// %1632 = call %struct.Memory* @_ZN12_GLOBAL__N_1L13StoreToOffsetI2RnIjE3MnWItEEEP6MemoryS6_R5StateT_T0_2InImE(%struct.Memory* %1631, %struct.State* %state2, i64 %1626, i64 %1628)

// TEST_BEGIN(STRH_32_LDST_POS, strh_w563_m16, 1)
// TEST_INPUTS(0)
//     add x3, sp, #-256
//     strh w5, [x3]
//     strh w6, [x3, #16]
//     strh w3, [x3, #32]
// TEST_END

/* STRH  <Wt>, [<Xn|SP>], #<simm> */
TEST_BEGIN(STRH_32_LDST_IMMPOST, strh_w56_m16_post, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    strh w5, [x3], #0
    strh w6, [x3], #32
TEST_END

/* STRH  <Wt>, [<Xn|SP>, #<simm>]! */
TEST_BEGIN(STRH_32_LDST_IMMPRE, strh_w5_m16_pre, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    strh w5, [x3, #16]!
TEST_END

/* STRH  <Wt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}] */
TEST_BEGIN(STRH_32_LDST_REGOFF, strh_w567_m16_off_w0_uxtw01, 1)
TEST_INPUTS(
    0,
    8)
    add x3, sp, #-256
    strh w5, [x3, ARG1_32, uxtw]
    strh w6, [x3, ARG1_32, uxtw #0]
    strh w7, [x3, ARG1_32, uxtw #1]
TEST_END

TEST_BEGIN(STRH_32_LDST_REGOFF, strh_w567_m16_off_w0_sxtw01, 1)
TEST_INPUTS(
    0,
    0xfffffff8)  /* -8 */
    add x3, sp, #-256
    strh w5, [x3, ARG1_32, sxtw]
    strh w6, [x3, ARG1_32, sxtw #0]
    strh w7, [x3, ARG1_32, sxtw #1]
TEST_END

/* STRH  <Wt>, [<Xn|SP>, <Xm>{, LSL <amount>}] */
TEST_BEGIN(STRH_32_LDST_REGOFF, strh_w567_m16_off_w0_lsl01, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    strh w5, [x3, ARG1_64]  /* Implicit LSL 0 */
    strh w6, [x3, ARG1_64, lsl #0]  /* Explicit LSL 0 */
    strh w7, [x3, ARG1_64, lsl #1]  /* Explicit LSL 1 */
TEST_END
