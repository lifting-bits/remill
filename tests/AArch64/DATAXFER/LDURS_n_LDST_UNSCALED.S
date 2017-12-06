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

/* LDURSB <Xt>, [<Xn|Sp>{, #<simm>}] */
TEST_BEGIN(LDURSB_32_LDST_UNSCALED, ldursb_w5_m8, 1)
TEST_INPUTS(0xFFFFFFFFFFFFFFFF)
    add x3, sp, #-256
    str ARG1_64, [x3, #0]
    ldursb w5, [x3, #0]
    ldursb w6, [x3, #8]
    ldursb w7, [x3, #16]
TEST_END
