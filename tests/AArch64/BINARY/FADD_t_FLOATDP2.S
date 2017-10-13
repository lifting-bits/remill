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

// FADD  <Sd>, <Sn>, <Sm>
TEST_BEGIN(FADD_S_FLOATDP2, fadd_s_floatdp2, 2)
TEST_INPUTS(
    0, 0,
    TEST_INPUTS_FP32)

    fmov s0, ARG1_32
    fmov s1, ARG2_32
    fadd s4, s0, s1
TEST_END

// FADD  <Dd>, <Dn>, <Dm>
TEST_BEGIN(FADD_D_FLOATDP2, fadd_d_floatdp2, 2)
TEST_INPUTS(
    0, 0,
    TEST_INPUTS_FP64)

    fmov d0, ARG1_64
    fmov d1, ARG2_64
    fadd d4, d0, d1
TEST_END
