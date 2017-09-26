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

/* LDP  <Wt1>, <Wt2>, [<Xn|SP>], #<imm> */
TEST_BEGIN(LDP_32_LDSTPAIR_POST, ldp_w0_w1_m64_post, 1)
TEST_INPUTS(0)

    add x3, sp, #-256
    ldp w4, w5, [x3], #0
    ldp w6, w7, [x3], #32
    ldp w8, w9, [x3], #64
TEST_END

/* LDP  <Xt1>, <Xt2>, [<Xn|SP>], #<imm> */
TEST_BEGIN(LDP_64_LDSTPAIR_POST, ldp_x0_x1_m128_post, 1)
TEST_INPUTS(0)

    add x3, sp, #-256
    ldp x4, x5, [x3], #0
    ldp x6, x7, [x3], #32
    ldp x8, x9, [x3], #64
TEST_END
