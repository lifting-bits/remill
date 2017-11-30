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

TEST_BEGIN(SCVTF_D32_FLOAT2INT, scvtf_d0_w0, 1)
TEST_INPUTS(
    0,
    1,
    0x80000000,
    0x7fffffff,
    0xffffffff)
    scvtf d0, ARG1_32
TEST_END

TEST_BEGIN(SCVTF_D64_FLOAT2INT, scvtf_d0_x0, 1)
TEST_INPUTS(
    0,
    1,
    0x80000000,
    0x7fffffff,
    0xffffffff,
    0x8000000000000000,
    0x7fffffffffffffff,
    0xffffffffffffffff)
    scvtf d0, ARG1_64
TEST_END


TEST_BEGIN(SCVTF_S32_FLOAT2INT, scvtf_s0_w0, 1)
TEST_INPUTS(
    0,
    1,
    0x80000000,
    0x7fffffff,
    0xffffffff)
    scvtf s0, ARG1_32
TEST_END

TEST_BEGIN(SCVTF_S64_FLOAT2INT, scvtf_s0_x0, 1)
TEST_INPUTS(
    0,
    1,
    0x80000000,
    0x7fffffff,
    0xffffffff,
    0x8000000000000000,
    0x7fffffffffffffff,
    0xffffffffffffffff)
    scvtf s0, ARG1_64
TEST_END
