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

TEST_BEGIN(STR_32_LDST_IMMPRE, str_w0_m32_pre, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    str w0, [x3, #0]!
    str w1, [x3, #16]!
    str w2, [x3, #32]!
TEST_END

TEST_BEGIN(STR_64_LDST_IMMPRE, str_x0_m64_pre, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    str x0, [x3, #0]!
    str x1, [x3, #16]!
    str x2, [x3, #32]!
TEST_END

TEST_BEGIN(STR_Q_LDST_IMMPRE, str_q0_m128_pre, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    str q0, [x3, #0]!
    str q1, [x3, #16]!
    str q3, [x3, #32]!
TEST_END
