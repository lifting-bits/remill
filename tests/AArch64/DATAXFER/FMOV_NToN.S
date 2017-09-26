
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

    fmov s0, w0
TEST_END

TEST_BEGIN(FMOV_64D_FLOAT2INT, fmov_f64_to_i64, 1)
TEST_INPUTS(0)
    fmov x0, d0
TEST_END

TEST_BEGIN(FMOV_D64_FLOAT2INT, fmov_i64_to_f64, 1)
TEST_INPUTS(
    0x3ff0000000000000 /* 1.000000 */,
    0x4000000000000000 /* 2.000000 */,
    0x3ff0000000000000 /* 1.000000 */,
    0xfff0000000000000 /* -inf */,
    0x7ff0000000000000 /* inf */, 
    0x7ff8000000000000 /* nan */
)
    fmov d0, x0
TEST_END