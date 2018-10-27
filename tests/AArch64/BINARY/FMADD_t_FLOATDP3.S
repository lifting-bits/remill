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

// FMADD  <Sd>, <Sn>, <Sm>, <Sa>
TEST_BEGIN(FMADD_S_FLOATDP3, fmadd_s_pos_floatdp3, 2)
TEST_INPUTS(
    0x00000000, 0x00000000,
    0x00000000, 0x00000001,
    0x3fffffff, 0x00000001, // WILL FAIL (Native no underflow, lifted says yes)
    0x3fffffff, 0x3fffffff,     
    0x3fffffff, 0x40000000,
    0x40000000, 0x3fffffff,    
    0x7FFFFFFF, 0x7FFFFFFF,
    0x80000000, 0x7FFFFFFF,     
    0x7FFFFFFF, 0x80000000,     
    0x80000000, 0x80000000,
    0xffffffff, 0xffffffff)

    fmov s0, ARG1_32
    fmov s1, ARG2_32
    fmov s2, #0x22
    fmadd s3, s0, s1, s2
TEST_END

TEST_BEGIN(FMADD_S_FLOATDP3, fmadd_s_neg_floatdp3, 2)
TEST_INPUTS(
    0x00000000, 0x00000000,
    0x00000000, 0x00000001,
    0x3fffffff, 0x00000001, // WILL FAIL (Native no underflow, lifted says yes)
    0x3fffffff, 0x3fffffff,     
    0x3fffffff, 0x40000000,     
    0x40000000, 0x3fffffff,    
    0x7FFFFFFF, 0x7FFFFFFF,
    0x80000000, 0x7FFFFFFF,     
    0x7FFFFFFF, 0x80000000,     
    0x80000000, 0x80000000,
    0xffffffff, 0xffffffff)

    fmov s0, ARG1_32
    fmov s1, ARG2_32
    fmov s2, -#0x22
    fmadd s3, s0, s1, s2
TEST_END

// FMADD  <Dd>, <Dn>, <Dm>, <Da>
TEST_BEGIN(FMADD_D_FLOATDP3, fmadd_d_pos_floatdp3, 2)
TEST_INPUTS(
    0x0000000000000000, 0x0000000000000000, // 0, 0
    0x0000000000000000, 0x0000000000000001, // 0, smallest representable float
    0x3fffffffffffffff, 0x0000000000000001, // 1.999999999999999, small float
    0x3fffffffffffffff, 0x3fffffffffffffff, // 1.999999999999999 for both
    0x3fffffffffffffff, 0x4000000000000000, // 1.999999999999999, 2.0
    0x4000000000000000, 0x3fffffffffffffff, // 2.0, 1.999999999999999
    0x7FFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF, // NaN, NaN
    0x8000000000000000, 0x7FFFFFFFFFFFFFFF, // -0.0, NaN
    0x7FFFFFFFFFFFFFFF, 0x8000000000000000, // NaN, -0.0
    0x8000000000000000, 0x8000000000000000, // -0.0, -0.0
    0xffffffffffffffff, 0xffffffffffffffff) // -NaN, -NaN

    fmov d0, ARG1_64
    fmov d1, ARG2_64
    fmov d2, #0x22
    fmadd d3, d0, d1, d2
TEST_END

TEST_BEGIN(FMADD_D_FLOATDP3, fmadd_d_neg_floatdp3, 2)
TEST_INPUTS(
    0x0000000000000000, 0x0000000000000000, // 0, 0
    0x0000000000000000, 0x0000000000000001, // 0, smallest representable float
    0x3fffffffffffffff, 0x0000000000000001, // 1.999999999999999, small float
    0x3fffffffffffffff, 0x3fffffffffffffff, // 1.999999999999999 for both
    0x3fffffffffffffff, 0x4000000000000000, // 1.999999999999999, 2.0
    0x4000000000000000, 0x3fffffffffffffff, // 2.0, 1.999999999999999
    0x7FFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF, // NaN, NaN
    0x8000000000000000, 0x7FFFFFFFFFFFFFFF, // -0.0, NaN
    0x7FFFFFFFFFFFFFFF, 0x8000000000000000, // NaN, -0.0
    0x8000000000000000, 0x8000000000000000, // -0.0, -0.0
    0xffffffffffffffff, 0xffffffffffffffff) // -NaN, -NaN

    fmov d0, ARG1_64
    fmov d1, ARG2_64
    fmov d2, -#0x22
    fmadd d3, d0, d1, d2
TEST_END