
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


TEST_BEGIN(FMOV_32S_FLOAT2INT, fmov_f32_to_i32, 1)
TEST_INPUTS(0)
    fmov w0, s0
    fmov w1, s0
    fmov w3, s2
    fmov w5, s4
    fmov w0, s5
TEST_END

TEST_BEGIN(FMOV_S32_FLOAT2INT, fmov_i32_to_f32, 1)
TEST_INPUTS(
    0x0,
    0x1,
    0x40,
    0x80,
    0x7f,
    0x3f,
    0x3fffffff, 
    0x40000000, 
    0x7FFFFFFF, 
    0x80000000)

    fmov s1, w0
TEST_END

TEST_BEGIN(FMOV_64D_FLOAT2INT, fmov_f64_to_i64, 1)
TEST_INPUTS(0)
    fmov x0, d0
    fmov x1, d0
    fmov x3, d2
    fmov x5, d4
    fmov x0, d5
TEST_END

TEST_BEGIN(FMOV_D64_FLOAT2INT, fmov_i64_to_f64, 1)
TEST_INPUTS(
    0x3ff0000000000000 /* 1.000000 */,
    0x4000000000000000 /* 2.000000 */,
    0x3ff0000000000000 /* 1.000000 */,
    0xfff0000000000000 /* -inf */,
    0x7ff0000000000000 /* inf */, 
    0x7ff8000000000000 /* nan */,
    0xC1F7FFFFFFD00000,
    0x41F7FFFFFFD00000
)
    fmov d1, x0
TEST_END

TEST_BEGIN(FMOV_S_FLOATDP1, fmov_s, 1)
TEST_INPUTS(0)
    fmov s1, s0
    fmov s3, s2
    fmov s5, s4
    fmov s0, s5
TEST_END

TEST_BEGIN(FMOV_D_FLOATDP1, fmov_d, 1)
TEST_INPUTS(0)
    fmov d1, d0
    fmov d3, d2
    fmov d5, d4
    fmov d0, d5
TEST_END
