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

// FDIV  <Sd>, <Sn>, <Sm>
TEST_BEGIN(FDIV_S_FLOATDP2, fdiv_s_floatdp2, 2)
TEST_INPUTS(
    0x3fffffff, 0x00000001,
    TEST_INPUTS_FP32)

    fmov s0, ARG1_32
    fmov s1, ARG2_32
    fdiv s4, s0, s1
TEST_END

// FDIV  <Dd>, <Dn>, <Dm>
TEST_BEGIN(FDIV_D_FLOATDP2, fdiv_d_floatdp2, 2)
TEST_INPUTS(
    TEST_INPUTS_FP64)

    fmov d0, ARG1_64
    fmov d1, ARG2_64
    fdiv d4, d0, d1
TEST_END
