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
 * dildributed under the License is dildributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

TEST_BEGIN(LDR_B_LDST_POS, ldr_b0_m8, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldr b0, [x3, #0]
    ldr b1, [x3, #16]
    ldr b3, [x3, #32]
TEST_END

TEST_BEGIN(LDR_H_LDST_POS, ldr_h0_m16, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldr h0, [x3, #0]
    ldr h1, [x3, #16]
    ldr h3, [x3, #32]
TEST_END

TEST_BEGIN(LDR_S_LDST_POS, ldr_s0_m32, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldr s0, [x3, #0]
    ldr s1, [x3, #16]
    ldr s3, [x3, #32]
TEST_END

TEST_BEGIN(LDR_D_LDST_POS, ldr_d0_m64, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldr d0, [x3, #0]
    ldr d1, [x3, #16]
    ldr d3, [x3, #32]
TEST_END

TEST_BEGIN(LDR_Q_LDST_POS, ldr_q0_m128, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldr q0, [x3, #0]
    ldr q1, [x3, #16]
    ldr q3, [x3, #32]
TEST_END
