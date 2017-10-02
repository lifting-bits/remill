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

/* STURB  <Wt>, [<Xn|SP>{, #<simm>}] */
TEST_BEGIN(STURB_32_LDST_UNSCALED, sturb_w5_m8, 3)
TEST_INPUTS(
    0x41414141, 0xabababab, 0xefefefef)

    add x3, sp, #-256
    sturb ARG1_32, [x3, #0]
    sturb ARG2_32, [x3, #8]
    sturb ARG3_32, [x3, #16]
TEST_END

/* STURH  <Wt>, [<Xn|SP>{, #<simm>}] */
TEST_BEGIN(STURH_32_LDST_UNSCALED, sturh_w5_m16, 3)
TEST_INPUTS(
    0x41414141, 0xabababab, 0xefefefef)

    add x3, sp, #-256
    sturh ARG1_32, [x3, #0]
    sturh ARG2_32, [x3, #8]
    sturh ARG3_32, [x3, #16]
TEST_END

/* STUR  <Wt>, [<Xn|SP>{, #<simm>}] */
TEST_BEGIN(STUR_32_LDST_UNSCALED, stur_w5_m32, 3)
TEST_INPUTS(
    0x41414141, 0xabababab, 0xefefefef)

    add x3, sp, #-256
    stur ARG1_32, [x3, #0]
    stur ARG2_32, [x3, #8]
    stur ARG3_32, [x3, #16]
TEST_END

/* STUR  <Xt>, [<Xn|SP>{, #<simm>}] */
TEST_BEGIN(STUR_64_LDST_UNSCALED, stur_x5_m64, 1)
TEST_INPUTS(
    0x4141414151515151, 0xababababcdcdcdcd, 0xefefefef01010101)

    add x3, sp, #-256
    stur ARG1_64, [x3, #0]
    stur ARG2_64, [x3, #8]
    stur ARG3_64, [x3, #16]
TEST_END
