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


TEST_BEGIN(FCMPE_S_FLOATCMP, fcmpe_s0_s1, 2)
TEST_INPUTS(
    0x00000000, 0x00000000,
    0x00000000, 0x00000001,
    0x3fffffff, 0x00000001,
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
    fcmpe s0, s1
TEST_END

TEST_BEGIN(FCMPE_SZ_FLOATCMP, fcmpe_z_s0_0, 1)
TEST_INPUTS(
    0x00000000, 
    0x3fffffff,      
    0x40000000,     
    0x7FFFFFFF, 
    0x80000000,      
    0xffffffff)

    fmov s0, ARG1_32
    fcmpe s0, #0.0
TEST_END

TEST_BEGIN(FCMP_S_FLOATCMP, fcmp_s0_s1, 2)
TEST_INPUTS(
    0x00000000, 0x00000000,
    0x00000000, 0x00000001,
    0x3fffffff, 0x00000001,
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
    fcmp s0, s1
TEST_END

TEST_BEGIN(FCMP_SZ_FLOATCMP, fcmp_z_s0_0, 1)
TEST_INPUTS(
    0x00000000, 
    0x3fffffff,      
    0x40000000,     
    0x7FFFFFFF, 
    0x80000000,      
    0xffffffff)

    fmov s0, ARG1_32
    fcmp s0, #0.0
TEST_END

TEST_BEGIN(FCMPE_D_FLOATCMP, fcmpe_d0_d1, 2)
TEST_INPUTS(
0x00000000, 0x00000000,
0x00000000, 0x00000001,
TEST_INPUTS_FP64)
    fmov d0, ARG1_64
    fmov d1, ARG2_64
    fcmpe d0, d1
TEST_END

TEST_BEGIN(FCMP_D_FLOATCMP, fcmp_d0_d1, 2)
TEST_INPUTS(
0x00000000, 0x00000000,
0x00000000, 0x00000001,
TEST_INPUTS_FP64)
    fmov d0, ARG1_64
    fmov d1, ARG2_64
    fcmp d0, d1
TEST_END

TEST_BEGIN(FCMP_DZ_FLOATCMP, fcmp_z_d0_0, 1)
TEST_INPUTS(
    0x00000000, 
    0x3fffffff,      
    0x40000000,     
    0x7FFFFFFF, 
    0x80000000,      
    0xffffffff,
    0xFFFFFFFFFFFFFFFF,
    0x3fffffffffffffff,
    0x7fffffffffffffff,
    0x8000000000000000, 
    0xfafbfbfdfafbfbfd, 
    0xfafbfbfd0a0b0c0d)

    fmov d0, ARG1_64
    fcmp d0, #0.0
TEST_END
