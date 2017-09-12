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


/* CLZ  <Wd>, <Wn> */
TEST_BEGIN(CLZ_32_DP_1SRC, clz_w1_w0, 1)
TEST_INPUTS(
    0,
    1,
    0xFFFFFFFF,
    0xfafbfbfd,
    0xf1f2f3f4,
    0x0a0b0c0d,
    0x01020304
)

    clz w1, w0
TEST_END

/* CLZ  <Xd>, <Xn> */
TEST_BEGIN(CLZ_64_DP_1SRC, clz_x1_x0, 1)
TEST_INPUTS(
    0,
    1,
    0,
    1,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0xf1f2f3f4,
    0x01020304,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFF00000000,
    0xFFFFFFFFFFFFFFFF,
    0xf1f2f3f4fafbfbfd,
    0x010203040a0b0c0d
)

    clz x1, x0;
TEST_END
