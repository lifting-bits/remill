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

/* LDP  <Xt1>, <Xt2>, [<Xn|SP>{, #<imm>}] */
TEST_BEGIN(LDPSW_64_LDSTPAIR_OFF, ldpsw_x0_x1_m64_off, 3)
TEST_INPUTS(0x00FFFFFFFFFFFFFF, 0xF0F0F0F0F0F0F0F0, 0x8080808080808080)
    add x3, sp, #-256
    str ARG1_64, [x3, #0]
    str ARG2_64, [x3, #64]
    str ARG3_64, [x3, #128]
    ldpsw x4, x5, [x3, #0]
    ldpsw x6, x7, [x3, #32]
    ldpsw x8, x9, [x3, #64]
TEST_END

/* LDPSW  <Xt1>, <Xt2>, [<Xn|SP>, #<imm>]! */
TEST_BEGIN(LDPSW_64_LDSTPAIR_PRE, ldpsw_x0_x1_m64_pre, 3)
TEST_INPUTS(0x00FFFFFFFFFFFFFF, 0xF0F0F0F0F0F0F0F0, 0x8080808080808080)
    add x3, sp, #-256
    str ARG1_64, [x3, #0]
    str ARG2_64, [x3, #64]
    str ARG3_64, [x3, #128]
    ldpsw x4, x5, [x3, #0]!
    ldpsw x6, x7, [x3, #32]!
    ldpsw x8, x9, [x3, #64]!
TEST_END

/* LDPSW  <Xt1>, <Xt2>, [<Xn|SP>], #<imm> */
TEST_BEGIN(LDPSW_64_LDSTPAIR_POST, ldpsw_x0_x1_m64_post, 3)
TEST_INPUTS(0x00FFFFFFFFFFFFFF, 0xF0F0F0F0F0F0F0F0, 0x8080808080808080)
    add x3, sp, #-256
    str ARG1_64, [x3, #0]
    str ARG2_64, [x3, #64]
    str ARG3_64, [x3, #128]
    ldpsw x4, x5, [x3], #0
    ldpsw x6, x7, [x3], #32
    ldpsw x8, x9, [x3], #64
TEST_END

