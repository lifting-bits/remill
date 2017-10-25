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

TEST_BEGIN(LD1_ASISDLSEP_I1_I1_16B, ld1_i1_16b, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ld1 {v0.16b}, [x3], #0x10
TEST_END

TEST_BEGIN(LD1_ASISDLSEP_I1_I1_8B, ld1_i1_8b, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ld1 {v0.8b}, [x3], #0x8
TEST_END

TEST_BEGIN(LD1_ASISDLSEP_I1_I1_8H, ld1_i1_8h, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ld1 {v1.8h}, [x3], #0x10
TEST_END

TEST_BEGIN(LD1_ASISDLSEP_I1_I1_4H, ld1_i1_4h, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ld1 {v0.4h}, [x3], #0x8
TEST_END

TEST_BEGIN(LD1_ASISDLSEP_I1_I1_4S, ld1_i1_4s, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ld1 {v0.4s}, [x3], #0x10
TEST_END

TEST_BEGIN(LD1_ASISDLSEP_I1_I1_2S, ld1_i1_2s, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ld1 {v0.2s}, [x3], #0x8
TEST_END

TEST_BEGIN(LD1_ASISDLSEP_I1_I1_2D, ld1_i1_2d, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ld1 {v0.2d}, [x3], #0x10
TEST_END

TEST_BEGIN(LD1_ASISDLSEP_I1_I1_1D, ld1_i1_1d, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    ld1 {v0.1d}, [x3], #0x8
TEST_END
