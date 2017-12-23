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

TEST_BEGIN(LD3_ASISDLSE_R3_16B, ld3_r3_16b, 1)
TEST_INPUTS(32)
    add x3, sp, #-256
    ld3 {v3.16b, v4.16b, v5.16b}, [x3]
TEST_END

TEST_BEGIN(LD3_ASISDLSE_R3_8B, ld3_r3_8b, 1)
TEST_INPUTS(32)
    add x3, sp, #-256
    ld3 {v3.8b, v4.8b, v5.8b}, [x3]
TEST_END

TEST_BEGIN(LD3_ASISDLSE_R3_4H, ld3_r3_4h, 1)
TEST_INPUTS(32)
    add x3, sp, #-256
    ld3 {v3.4h, v4.4h, v5.4h}, [x3]
TEST_END

TEST_BEGIN(LD3_ASISDLSE_R3_8H, ld3_r3_8h, 1)
TEST_INPUTS(32)
    add x3, sp, #-256
    ld3 {v3.8h, v4.8h, v5.8h}, [x3]
TEST_END

TEST_BEGIN(LD3_ASISDLSE_R3_4S, ld3_r3_4s, 1)
TEST_INPUTS(32)
    add x3, sp, #-256
    ld3 {v3.4s, v4.4s, v5.4s}, [x3]
TEST_END

TEST_BEGIN(LD3_ASISDLSE_R3_2S, ld3_r3_2s, 1)
TEST_INPUTS(32)
    add x3, sp, #-256
    ld3 {v3.2s, v4.2s, v5.2s}, [x3]
TEST_END

TEST_BEGIN(LD3_ASISDLSE_R3_2D, ld3_r3_2d, 1)
TEST_INPUTS(32)
    add x3, sp, #-256
    ld3 {v3.2d, v4.2d, v5.2d}, [x3]
TEST_END
