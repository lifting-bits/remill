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


TEST_BEGIN(FCVTZU_32S_FLOAT2INT, fcvtzu_w0_s0, 1)
TEST_INPUTS(
    0,
    1,
    0x80000000,
    0x7fffffff,
    0xffffffff,
    0x3fffffff,
    0xbf800000,
    0xc0000000)    
    fmov s0, ARG1_32
    fcvtzu w0, s0
TEST_END

TEST_BEGIN(FCVTZU_64S_FLOAT2INT, fcvtzu_x0_s0, 1)
TEST_INPUTS(
    0,
    1,
    0x80000000,
    0x7fffffff,
    0xffffffff,
    0x3fffffff,
    0xbf800000,
    0xc0000000)

    fmov s0, ARG1_32
    fcvtzu x0, s0
TEST_END

TEST_BEGIN(FCVTZU_32D_FLOAT2INT, fcvtzu_w0_d0, 1)
TEST_INPUTS(
    0,
    1,
    0x80000000,
    0x7fffffff,
    0xffffffff,
    0x3fffffff,
    0xbf800000,
    0xc0000000)

    fmov d0, ARG1_64
    fcvtzu w0, d0
TEST_END

TEST_BEGIN(FCVTZU_64D_FLOAT2INT, fcvtzu_x0_d0, 1)
TEST_INPUTS(
    0,
    1,
    0x80000000,
    0x7fffffff,
    0xffffffff,
    0x3fffffff,
    0xbf800000,
    0xc0000000)

    fmov d0, ARG1_64
    fcvtzu x0, d0
TEST_END

TEST_BEGIN(FCVTZS_32D_FLOAT2INT, fcvtzs_w0_d0, 1)
TEST_INPUTS(
    0,
    1,
    0x80000000,
    0x7fffffff,
    0xffffffff,
    0x3fffffff,   
    0xbf800000,
    0xc0000000,
    0x41F7FFFFFFD00000)

    fmov d0, ARG1_64
    fcvtzs w0, d0
TEST_END

TEST_BEGIN(FCVTZS_32S_FLOAT2INT, fcvtzs_w0_s0, 1)
TEST_INPUTS(
    0,
    1,
    0x80000000,
    0x7fffffff,
    0xffffffff,
    0x3fffffff,
    0xbf800000,
    0xc0000000)    
    fmov s0, ARG1_32
    fcvtzs w0, s0
TEST_END

TEST_BEGIN(FCVTZS_64D_FLOAT2INT, fcvtzs_x0_d0, 1)
TEST_INPUTS(
    0,
    1,
    0x80000000,
    0x7fffffff,
    0xffffffff,
    0x3fffffff,
    0xbf800000,
    0xc0000000,
    0x41F7FFFFFFD00000)

    fmov d0, ARG1_64
    fcvtzs x0, d0
TEST_END
