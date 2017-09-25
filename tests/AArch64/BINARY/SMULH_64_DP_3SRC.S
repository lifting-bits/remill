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

TEST_BEGIN(SMULH_64_DP_3SRC, smulh_x3_x0_x1, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304,

    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    0xfafbfbfdfafbfbfd, 0xf1f2f3f4f1f2f3f4,
    0xfafbfbfd0a0b0c0d, 0x01020304f1f2f3f4)

    smulh x3, ARG1_64, ARG2_64
TEST_END
