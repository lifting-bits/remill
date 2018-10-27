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

TEST_BEGIN(LD4_ASISDLSE_R4_16B, ld4_r4_16b, 1)
TEST_INPUTS(32)
    add x3, sp, #-256
    ld4 {v3.16b, v4.16b, v5.16b, v6.16b}, [x3]
TEST_END

TEST_BEGIN(LD4_ASISDLSE_R4_8B, ld4_r4_8b, 1)
TEST_INPUTS(32)
    add x3, sp, #-256
    ld4 {v3.8b, v4.8b, v5.8b, v6.8b}, [x3]
TEST_END

TEST_BEGIN(LD4_ASISDLSE_R4_4H, ld4_r4_4h, 1)
TEST_INPUTS(32)
    add x3, sp, #-256
    ld4 {v3.4h, v4.4h, v5.4h, v6.4h}, [x3]
TEST_END

TEST_BEGIN(LD4_ASISDLSE_R4_8H, ld4_r4_8h, 1)
TEST_INPUTS(32)
    add x3, sp, #-256
    ld4 {v3.8h, v4.8h, v5.8h, v6.8h}, [x3]
TEST_END

TEST_BEGIN(LD4_ASISDLSE_R4_4S, ld4_r4_4s, 1)
TEST_INPUTS(32)
    add x3, sp, #-256
    ld4 {v3.4s, v4.4s, v5.4s, v6.4s}, [x3]
TEST_END

TEST_BEGIN(LD4_ASISDLSE_R4_2S, ld4_r4_2s, 1)
TEST_INPUTS(32)
    add x3, sp, #-256
    ld4 {v3.2s, v4.2s, v5.2s, v6.2s}, [x3]
TEST_END

TEST_BEGIN(LD4_ASISDLSE_R4_2D, ld4_r4_2d, 1)
TEST_INPUTS(32)
    add x3, sp, #-256
    ld4 {v3.2d, v4.2d, v5.2d, v6.2d}, [x3]
TEST_END
