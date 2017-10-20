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

TEST_BEGIN(DUP_ASIMDINS_DR_R_8B, dup_v0x8b_w0, 1)
TEST_INPUTS(0xaa)
    dup v0.8b, ARG1_32
TEST_END

TEST_BEGIN(DUP_ASIMDINS_DR_R_16B, dup_v0x16b_w0, 1)
TEST_INPUTS(0xaa)
    dup v0.16b, ARG1_32
TEST_END

TEST_BEGIN(DUP_ASIMDINS_DR_R_4H, dup_v0x4h_w0, 1)
TEST_INPUTS(0xaabb)
    dup v0.4h, ARG1_32
TEST_END

TEST_BEGIN(DUP_ASIMDINS_DR_R_8H, dup_v0x8h_w0, 1)
TEST_INPUTS(0xaabb)
    dup v0.8h, ARG1_32
TEST_END

TEST_BEGIN(DUP_ASIMDINS_DR_R_2S, dup_v0x2s_w0, 1)
TEST_INPUTS(0xaabbccdd)
    dup v0.2s, ARG1_32
TEST_END

TEST_BEGIN(DUP_ASIMDINS_DR_R_4S, dup_v0x4s_w0, 1)
TEST_INPUTS(0xaabbccdd)
    dup v0.4s, ARG1_32
TEST_END

TEST_BEGIN(DUP_ASIMDINS_DR_R_2D, dup_v0x2d_x0, 1)
TEST_INPUTS(0xaabbccdd11223344)
    dup v0.2d, ARG1_64
TEST_END
