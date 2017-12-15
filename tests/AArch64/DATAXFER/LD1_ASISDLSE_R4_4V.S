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

TEST_BEGIN(LD1_ASISDLSE_R4_4V_16B, ld1_r4_16b, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ld1 {v31.16b, v0.16b, v1.16b, v2.16b}, [x3]
TEST_END

TEST_BEGIN(LD1_ASISDLSE_R4_4V_8B, ld1_r4_8b, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ld1 {v31.8b, v0.8b, v1.8b, v2.8b}, [x3]
TEST_END

TEST_BEGIN(LD1_ASISDLSE_R4_4V_8H, ld1_r4_8h, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ld1 {v31.8h, v0.8h, v1.8h, v2.8h}, [x3]
TEST_END

TEST_BEGIN(LD1_ASISDLSE_R4_4V_4H, ld1_r4_4h, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ld1 {v31.4h, v0.4h, v1.4h, v2.4h}, [x3]
TEST_END

TEST_BEGIN(LD1_ASISDLSE_R4_4V_4S, ld1_r4_4s, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ld1 {v31.4s, v0.4s, v1.4s, v2.4s}, [x3]
TEST_END

TEST_BEGIN(LD1_ASISDLSE_R4_4V_2S, ld1_r4_2s, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ld1 {v31.2s, v0.2s, v1.2s, v2.2s}, [x3]
TEST_END

TEST_BEGIN(LD1_ASISDLSE_R4_4V_2D, ld1_r4_2d, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ld1 {v31.2d, v0.2d, v1.2d, v2.2d}, [x3]
TEST_END

TEST_BEGIN(LD1_ASISDLSE_R4_4V_1D, ld1_r4_1d, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ld1 {v31.1d, v0.1d, v1.1d, v2.1d}, [x3]
TEST_END
