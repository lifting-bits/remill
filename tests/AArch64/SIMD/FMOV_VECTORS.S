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

TEST_BEGIN(FMOV_64VX_FLOAT2INT, fmov_64vx, 1)
TEST_INPUTS(0)
    fmov x0, v0.d[1]
    fmov x1, v1.d[1]
    fmov x2, v2.d[1]
    fmov x3, v3.d[1]
    fmov x4, v4.d[1]
    fmov x5, v5.d[1]
    fmov x6, v6.d[1]
    fmov x0, v6.d[1]
TEST_END

TEST_BEGIN(FMOV_V64I_FLOAT2INT, fmov_v64i, 1)
TEST_INPUTS(0)
    fmov v0.d[1], x0
    fmov v1.d[1], x1
    fmov v2.d[1], x2
    fmov v3.d[1], x3
    fmov v4.d[1], x4
    fmov v5.d[1], x5
    fmov v6.d[1], x6
    fmov v0.d[1], x6
TEST_END