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

TEST_BEGIN(STR_32_LDST_POS, str_w0_m32, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    str w0, [x3, #0]
    str w1, [x3, #16]
    str w2, [x3, #32]
TEST_END

TEST_BEGIN(STR_64_LDST_POS, str_x0_m64, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    str x0, [x3, #0]
    str x1, [x3, #16]
    str x2, [x3, #32]
TEST_END

TEST_BEGIN(STR_B_LDST_POS, str_b0_m8, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    str b0, [x3, #0]
    str b1, [x3, #16]
    str b3, [x3, #32]
TEST_END

TEST_BEGIN(STR_H_LDST_POS, str_h0_m16, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    str h0, [x3, #0]
    str h1, [x3, #16]
    str h3, [x3, #32]
TEST_END

TEST_BEGIN(STR_S_LDST_POS, str_s0_m32, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    str s0, [x3, #0]
    str s1, [x3, #16]
    str s3, [x3, #32]
TEST_END

TEST_BEGIN(STR_D_LDST_POS, str_d0_m64, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    str d0, [x3, #0]
    str d1, [x3, #16]
    str d3, [x3, #32]
TEST_END

TEST_BEGIN(STR_Q_LDST_POS, str_q0_m128, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    str q0, [x3, #0]
    str q1, [x3, #16]
    str q3, [x3, #32]
TEST_END
