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

/* LDUR  <Wt>, [<Xn|SP>{, #<simm>}] */
TEST_BEGIN(LDUR_32_LDST_UNSCALED, ldur_w5_m32, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldur w5, [x3, #0]
    ldur w6, [x3, #8]
    ldur w7, [x3, #16]
TEST_END

/* LDUR  <Xt>, [<Xn|SP>{, #<simm>}] */
TEST_BEGIN(LDUR_64_LDST_UNSCALED, ldur_x5_m64, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ldur x5, [x3, #0]
    ldur x6, [x3, #8]
    ldur x7, [x3, #16]
TEST_END
