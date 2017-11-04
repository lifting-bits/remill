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

// FMUL  <Sd>, <Sn>, <Sm>
TEST_BEGIN(FMUL_S_FLOATDP2, fmul_s_floatdp2, 2)
TEST_INPUTS(
    0, 0,
    0x3fffffff, 0x00000001,
    TEST_INPUTS_FP32)

    fmov s0, ARG1_32
    fmov s1, ARG2_32
    fmul s4, s0, s1
TEST_END

// FMUL  <Dd>, <Dn>, <Dm>
TEST_BEGIN(FMUL_D_FLOATDP2, fmul_d_floatdp2, 2)
TEST_INPUTS(
    0x00000000, 0x00000000,
    0x00000000, 0x00000001,
    TEST_INPUTS_FP64)

    fmov d0, ARG1_64
    fmov d1, ARG2_64
    fmul d4, d0, d1
TEST_END
