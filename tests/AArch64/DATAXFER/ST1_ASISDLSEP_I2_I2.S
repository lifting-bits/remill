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

TEST_BEGIN(ST1_ASISDLSEP_I2_I2_16B, st1_i2_16b, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    st1 {v3.16b, v4.16b}, [x3], #0x20
    st1 {v31.16b, v0.16b}, [x3], #0x20
TEST_END

TEST_BEGIN(ST1_ASISDLSEP_I2_I2_8B, st1_i2_8b, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    st1 {v3.8b, v4.8b}, [x3], #0x10
    st1 {v31.8b, v0.8b}, [x3], #0x10
TEST_END

TEST_BEGIN(ST1_ASISDLSEP_I2_I2_8H, st1_i2_8h, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    st1 {v3.8h, v4.8h}, [x3], #0x20
    st1 {v31.8h, v0.8h}, [x3], #0x20
TEST_END

TEST_BEGIN(ST1_ASISDLSEP_I2_I2_4H, st1_i2_4h, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    st1 {v3.4h, v4.4h}, [x3], #0x10
    st1 {v31.4h, v0.4h}, [x3], #0x10
TEST_END

TEST_BEGIN(ST1_ASISDLSEP_I2_I2_4S, st1_i2_4s, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    st1 {v3.4s, v4.4s}, [x3], #0x20
    st1 {v31.4s, v0.4s}, [x3], #0x20
TEST_END

TEST_BEGIN(ST1_ASISDLSEP_I2_I2_2S, st1_i2_2s, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    st1 {v3.2s, v4.2s}, [x3], #0x10
    st1 {v31.2s, v0.2s}, [x3], #0x10
TEST_END

TEST_BEGIN(ST1_ASISDLSEP_I2_I2_2D, st1_i2_2d, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    st1 {v3.2d, v4.2d}, [x3], #0x20
    st1 {v31.2d, v0.2d}, [x3], #0x20
TEST_END

TEST_BEGIN(ST1_ASISDLSEP_I2_I2_1D, st1_i2_1d, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    st1 {v3.1d, v4.1d}, [x3], #0x10
    st1 {v31.1d, v0.1d}, [x3], #0x10
TEST_END
