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

