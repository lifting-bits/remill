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

TEST_BEGIN(LD1_ASISDLSE_R1_1V_16B, ld1_r1_16b, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ld1 {v0.16b}, [x3]
TEST_END

TEST_BEGIN(LD1_ASISDLSE_R1_1V_8B, ld1_r1_8b, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ld1 {v0.8b}, [x3]
TEST_END

TEST_BEGIN(LD1_ASISDLSE_R1_1V_8H, ld1_r1_8h, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ld1 {v1.8h}, [x3]
TEST_END

TEST_BEGIN(LD1_ASISDLSE_R1_1V_4H, ld1_r1_4h, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ld1 {v0.4h}, [x3]
TEST_END

TEST_BEGIN(LD1_ASISDLSE_R1_1V_4S, ld1_r1_4s, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ld1 {v0.4s}, [x3]
TEST_END

TEST_BEGIN(LD1_ASISDLSE_R1_1V_2S, ld1_r1_2s, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ld1 {v0.2s}, [x3]
TEST_END

TEST_BEGIN(LD1_ASISDLSE_R1_1V_2D, ld1_r1_2d, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ld1 {v0.2d}, [x3]
TEST_END

TEST_BEGIN(LD1_ASISDLSE_R1_1V_1D, ld1_r1_1d, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ld1 {v0.1d}, [x3]
TEST_END
