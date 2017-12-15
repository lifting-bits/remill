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

TEST_BEGIN(LD2_ASISDLSEP_R2_R_16B, ld2_r2_r_16b, 1)
TEST_INPUTS(32)
    add x3, sp, #-256
    ld2 {v3.16b, v4.16b}, [x3], ARG1_64
TEST_END

TEST_BEGIN(LD2_ASISDLSEP_R2_R_8B, ld2_r2_r_8b, 1)
TEST_INPUTS(32)
    add x3, sp, #-256
    ld2 {v3.8b, v4.8b}, [x3], ARG1_64
TEST_END

TEST_BEGIN(LD2_ASISDLSEP_R2_R_4H, ld2_r2_r_4h, 1)
TEST_INPUTS(32)
    add x3, sp, #-256
    ld2 {v3.4h, v4.4h}, [x3], ARG1_64
TEST_END

TEST_BEGIN(LD2_ASISDLSEP_R2_R_8H, ld2_r2_r_8h, 1)
TEST_INPUTS(32)
    add x3, sp, #-256
    ld2 {v3.8h, v4.8h}, [x3], ARG1_64
TEST_END

TEST_BEGIN(LD2_ASISDLSEP_R2_R_4S, ld2_r2_r_4s, 1)
TEST_INPUTS(32)
    add x3, sp, #-256
    ld2 {v3.4s, v4.4s}, [x3], ARG1_64
TEST_END

TEST_BEGIN(LD2_ASISDLSEP_R2_R_2S, ld2_r2_r_2s, 1)
TEST_INPUTS(32)
    add x3, sp, #-256
    ld2 {v3.2s, v4.2s}, [x3], ARG1_64
TEST_END

TEST_BEGIN(LD2_ASISDLSEP_R2_R_2D, ld2_r2_r_2d, 1)
TEST_INPUTS(32)
    add x3, sp, #-256
    ld2 {v3.2d, v4.2d}, [x3], ARG1_64
TEST_END
