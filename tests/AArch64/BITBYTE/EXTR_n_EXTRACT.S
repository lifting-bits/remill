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

/* ROR  <Xd>, <Xn>, #<lsb> */
TEST_BEGIN(EXTR_32_EXTRACT, ror_w3_w0_0, 1)
TEST_INPUTS(
    0x44556677)

    ror w3, ARG1_32, #0
TEST_END

TEST_BEGIN(EXTR_32_EXTRACT, ror_w3_w0_19, 1)
TEST_INPUTS(
    0x44556677)

    ror w3, ARG1_32, #19
TEST_END

TEST_BEGIN(EXTR_32_EXTRACT, ror_w3_w0_31, 1)
TEST_INPUTS(
    0x44556677)

    ror w3, ARG1_32, #31
TEST_END

/* EXTR  <Xd>, <Xn>, <Xm>, #<lsb> */
TEST_BEGIN(EXTR_32_EXTRACT, extr_w3_w0_w1_0, 2)
TEST_INPUTS(
    0x44556677, 0xaabbccdd)

    extr w3, ARG1_32, ARG2_32, #0
TEST_END

TEST_BEGIN(EXTR_32_EXTRACT, extr_w3_w0_w1_17, 2)
TEST_INPUTS(
    0x44556677, 0xaabbccdd)

    extr w3, ARG1_32, ARG2_32, #17
TEST_END

TEST_BEGIN(EXTR_32_EXTRACT, extr_w3_w0_w1_31, 2)
TEST_INPUTS(
    0x44556677, 0xaabbccdd)

    extr w3, ARG1_32, ARG2_32, #31
TEST_END


/* ROR  <Xd>, <Xn>, #<lsb> */
TEST_BEGIN(EXTR_64_EXTRACT, ror_x3_x0_0, 1)
TEST_INPUTS(
    0x445566778899eeff)

    ror x3, ARG1_64, #0
TEST_END

TEST_BEGIN(EXTR_64_EXTRACT, ror_x3_x0_19, 1)
TEST_INPUTS(
    0x445566778899eeff)

    ror x3, ARG1_64, #19
TEST_END

TEST_BEGIN(EXTR_64_EXTRACT, ror_x3_x0_63, 1)
TEST_INPUTS(
    0x445566778899eeff)

    ror x3, ARG1_64, #63
TEST_END

/* EXTR  <Xd>, <Xn>, <Xm>, #<lsb> */
TEST_BEGIN(EXTR_64_EXTRACT, extr_x3_x0_x1_0, 2)
TEST_INPUTS(
    0x445566778899eeff, 0xaabbccdd00112233)

    extr x3, ARG1_64, ARG2_64, #0
TEST_END

TEST_BEGIN(EXTR_64_EXTRACT, extr_x3_x0_x1_17, 2)
TEST_INPUTS(
    0x445566778899eeff, 0xaabbccdd00112233)

    extr x3, ARG1_64, ARG2_64, #17
TEST_END

TEST_BEGIN(EXTR_64_EXTRACT, extr_x3_x0_x1_31, 2)
TEST_INPUTS(
    0x445566778899eeff, 0xaabbccdd00112233)

    extr x3, ARG1_64, ARG2_64, #31
TEST_END


TEST_BEGIN(EXTR_64_EXTRACT, extr_x3_x0_x1_32, 2)
TEST_INPUTS(
    0x445566778899eeff, 0xaabbccdd00112233)

    extr x3, ARG1_64, ARG2_64, #32
TEST_END

TEST_BEGIN(EXTR_64_EXTRACT, extr_x3_x0_x1_63, 2)
TEST_INPUTS(
    0x445566778899eeff, 0xaabbccdd00112233)

    extr x0, ARG1_64, ARG2_64, #63
TEST_END

