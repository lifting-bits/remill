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

TEST_BEGIN(MINSSv128v128m32, 2)
TEST_INPUTS(
    0.0, 1.2,
    3.4, 2.3,
    5.5, 5.5,
    0x7fc00000, 0x7fc00000, /* nan, nan */ 
    0x7fc00000, 0xffc00000, /* nan, -nan */ 
    0xffc00000, 0x7fc00000, /* -nan, nan */ 
    0x7fbfffff, 0x7fbfffff, /* nan, nan */ 
    0xffbfffff, 0xffbfffff, /* -nan, -nan */ 
    0x7fbfffff, 0xffbfffff, /* nan, -nan */ 
    0xffbfffff, 0x7fbfffff, /* -nan, nan */ 
    0x7f800000, 0x7f800000, /* inf, inf */ 
    0x7f800000, 0xff800000, /* inf, -inf */ 
    0xff800000, 0x7f800000, /* -inf, inf */ 
    0x00000000, 0x00000000, /* 0.000000, 0.000000 */ 
    0x00000000, 0x80000000, /* 0.000000, -0.000000 */ 
    0x80000000, 0x00000000, /* -0.000000, 0.000000 */ 
    0x3f800000, 0x7fc00000, /* 1.000000, nan */ 
    0x7fc00000, 0x3f800000, /* nan, 1.000000 */ 
    0x3f800000, 0x7fc00000, /* 1.000000, nan */ 
    0x3f800000, 0x7fbfffff, /* 1.000000, nan */ 
    0x7fbfffff, 0x3f800000, /* nan, 1.000000 */ 
    0x3f800000, 0x7fbfffff, /* 1.000000, nan */ 
    0x7f800000, 0x7fc00000, /* inf, nan */ 
    0x7fc00000, 0x7f800000, /* nan, inf */ 
    0x7f800000, 0x7fbfffff, /* inf, nan */ 
    0x7fbfffff, 0x7f800000, /* nan, inf */ 
    0x3f800000, 0x7f800000, /* 1.000000, inf */ 
    0x3f800000, 0xff800000, /* 1.000000, -inf */ 
    0x7f800000, 0x3f800000, /* inf, 1.000000 */ 
    0xff800000, 0x3f800000, /* -inf, 1.000000 */ 
    0x3f800000, 0xbf800000, /* 1.000000, -1.000000 */ 
    0xbf800000, 0x3f800000) /* -1.000000, 1.000000 */
    push ARG1_32;
    push ARG2_32;
    movq xmm0, qword ptr [rsp + 8];  // ???
    movq xmm1, qword ptr [rsp];      // ???
    minss xmm0, xmm1;                // ???
TEST_END

TEST_BEGIN(MINSSv128v128v128, 2)
TEST_INPUTS(
    0.0, 1.2,
    3.4, 2.3,
    5.5, 5.5,
    0x7fc00000, 0x7fc00000, /* nan, nan */ 
    0x7fc00000, 0xffc00000, /* nan, -nan */ 
    0xffc00000, 0x7fc00000, /* -nan, nan */ 
    0x7fbfffff, 0x7fbfffff, /* nan, nan */ 
    0xffbfffff, 0xffbfffff, /* -nan, -nan */ 
    0x7fbfffff, 0xffbfffff, /* nan, -nan */ 
    0xffbfffff, 0x7fbfffff, /* -nan, nan */ 
    0x7f800000, 0x7f800000, /* inf, inf */ 
    0x7f800000, 0xff800000, /* inf, -inf */ 
    0xff800000, 0x7f800000, /* -inf, inf */ 
    0x00000000, 0x00000000, /* 0.000000, 0.000000 */ 
    0x00000000, 0x80000000, /* 0.000000, -0.000000 */ 
    0x80000000, 0x00000000, /* -0.000000, 0.000000 */ 
    0x3f800000, 0x7fc00000, /* 1.000000, nan */ 
    0x7fc00000, 0x3f800000, /* nan, 1.000000 */ 
    0x3f800000, 0x7fc00000, /* 1.000000, nan */ 
    0x3f800000, 0x7fbfffff, /* 1.000000, nan */ 
    0x7fbfffff, 0x3f800000, /* nan, 1.000000 */ 
    0x3f800000, 0x7fbfffff, /* 1.000000, nan */ 
    0x7f800000, 0x7fc00000, /* inf, nan */ 
    0x7fc00000, 0x7f800000, /* nan, inf */ 
    0x7f800000, 0x7fbfffff, /* inf, nan */ 
    0x7fbfffff, 0x7f800000, /* nan, inf */ 
    0x3f800000, 0x7f800000, /* 1.000000, inf */ 
    0x3f800000, 0xff800000, /* 1.000000, -inf */ 
    0x7f800000, 0x3f800000, /* inf, 1.000000 */ 
    0xff800000, 0x3f800000, /* -inf, 1.000000 */ 
    0x3f800000, 0xbf800000, /* 1.000000, -1.000000 */ 
    0xbf800000, 0x3f800000) /* -1.000000, 1.000000 */
    push ARG1_32;
    push ARG2_32;
    movq xmm0, qword ptr [rsp + 8];  // ???
    movq xmm1, qword ptr [rsp];      // ???
    minss xmm0, xmm1;                // ???
TEST_END

TEST_BEGIN(MINSSvv128vv128mv128, 2)
TEST_INPUTS(
    0.0, 1.2,
    3.4, 2.3,
    5.5, 5.5,
    0x7fc00000, 0x7fc00000, /* nan, nan */ 
    0x7fc00000, 0xffc00000, /* nan, -nan */ 
    0xffc00000, 0x7fc00000, /* -nan, nan */ 
    0x7fbfffff, 0x7fbfffff, /* nan, nan */ 
    0xffbfffff, 0xffbfffff, /* -nan, -nan */ 
    0x7fbfffff, 0xffbfffff, /* nan, -nan */ 
    0xffbfffff, 0x7fbfffff, /* -nan, nan */ 
    0x7f800000, 0x7f800000, /* inf, inf */ 
    0x7f800000, 0xff800000, /* inf, -inf */ 
    0xff800000, 0x7f800000, /* -inf, inf */ 
    0x00000000, 0x00000000, /* 0.000000, 0.000000 */ 
    0x00000000, 0x80000000, /* 0.000000, -0.000000 */ 
    0x80000000, 0x00000000, /* -0.000000, 0.000000 */ 
    0x3f800000, 0x7fc00000, /* 1.000000, nan */ 
    0x7fc00000, 0x3f800000, /* nan, 1.000000 */ 
    0x3f800000, 0x7fc00000, /* 1.000000, nan */ 
    0x3f800000, 0x7fbfffff, /* 1.000000, nan */ 
    0x7fbfffff, 0x3f800000, /* nan, 1.000000 */ 
    0x3f800000, 0x7fbfffff, /* 1.000000, nan */ 
    0x7f800000, 0x7fc00000, /* inf, nan */ 
    0x7fc00000, 0x7f800000, /* nan, inf */ 
    0x7f800000, 0x7fbfffff, /* inf, nan */ 
    0x7fbfffff, 0x7f800000, /* nan, inf */ 
    0x3f800000, 0x7f800000, /* 1.000000, inf */ 
    0x3f800000, 0xff800000, /* 1.000000, -inf */ 
    0x7f800000, 0x3f800000, /* inf, 1.000000 */ 
    0xff800000, 0x3f800000, /* -inf, 1.000000 */ 
    0x3f800000, 0xbf800000, /* 1.000000, -1.000000 */ 
    0xbf800000, 0x3f800000) /* -1.000000, 1.000000 */
    push ARG1_32;
    push ARG2_32;
    movq xmm0, qword ptr [rsp + 8];  // ???
    movq xmm1, qword ptr [rsp];      // ???
    minss xmm0, xmm1;                // ???
TEST_END

TEST_BEGIN(MINSSvv128vv128vv128, 2)
TEST_INPUTS(
    0.0, 1.2,
    3.4, 2.3,
    5.5, 5.5,
    0x7fc00000, 0x7fc00000, /* nan, nan */ 
    0x7fc00000, 0xffc00000, /* nan, -nan */ 
    0xffc00000, 0x7fc00000, /* -nan, nan */ 
    0x7fbfffff, 0x7fbfffff, /* nan, nan */ 
    0xffbfffff, 0xffbfffff, /* -nan, -nan */ 
    0x7fbfffff, 0xffbfffff, /* nan, -nan */ 
    0xffbfffff, 0x7fbfffff, /* -nan, nan */ 
    0x7f800000, 0x7f800000, /* inf, inf */ 
    0x7f800000, 0xff800000, /* inf, -inf */ 
    0xff800000, 0x7f800000, /* -inf, inf */ 
    0x00000000, 0x00000000, /* 0.000000, 0.000000 */ 
    0x00000000, 0x80000000, /* 0.000000, -0.000000 */ 
    0x80000000, 0x00000000, /* -0.000000, 0.000000 */ 
    0x3f800000, 0x7fc00000, /* 1.000000, nan */ 
    0x7fc00000, 0x3f800000, /* nan, 1.000000 */ 
    0x3f800000, 0x7fc00000, /* 1.000000, nan */ 
    0x3f800000, 0x7fbfffff, /* 1.000000, nan */ 
    0x7fbfffff, 0x3f800000, /* nan, 1.000000 */ 
    0x3f800000, 0x7fbfffff, /* 1.000000, nan */ 
    0x7f800000, 0x7fc00000, /* inf, nan */ 
    0x7fc00000, 0x7f800000, /* nan, inf */ 
    0x7f800000, 0x7fbfffff, /* inf, nan */ 
    0x7fbfffff, 0x7f800000, /* nan, inf */ 
    0x3f800000, 0x7f800000, /* 1.000000, inf */ 
    0x3f800000, 0xff800000, /* 1.000000, -inf */ 
    0x7f800000, 0x3f800000, /* inf, 1.000000 */ 
    0xff800000, 0x3f800000, /* -inf, 1.000000 */ 
    0x3f800000, 0xbf800000, /* 1.000000, -1.000000 */ 
    0xbf800000, 0x3f800000) /* -1.000000, 1.000000 */
    push ARG1_32;
    push ARG2_32;
    movq xmm0, qword ptr [rsp + 8];  // ???
    movq xmm1, qword ptr [rsp];      // ???
    minss xmm0, xmm1;                // ???
TEST_END
