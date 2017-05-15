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

#if HAS_FEATURE_AVX

# define MAKE_VCMPSS_TEST(op) \
    TEST_BEGIN_64(VCMPSSv128v128v128i8_##op, 2) \
    TEST_INPUTS( \
        0x7fc00000, 0x7fc00000, /* nan, nan */ \
        0x7fc00000, 0xffc00000, /* nan, -nan */ \
        0xffc00000, 0x7fc00000, /* -nan, nan */ \
        0x7fbfffff, 0x7fbfffff, /* nan, nan */ \
        0xffbfffff, 0xffbfffff, /* -nan, -nan */ \
        0x7fbfffff, 0xffbfffff, /* nan, -nan */ \
        0xffbfffff, 0x7fbfffff, /* -nan, nan */ \
        0x7f800000, 0x7f800000, /* inf, inf */ \
        0x7f800000, 0xff800000, /* inf, -inf */ \
        0xff800000, 0x7f800000, /* -inf, inf */ \
        0x00000000, 0x00000000, /* 0.000000, 0.000000 */ \
        0x00000000, 0x80000000, /* 0.000000, -0.000000 */ \
        0x80000000, 0x00000000, /* -0.000000, 0.000000 */ \
        0x3f800000, 0x7fc00000, /* 1.000000, nan */ \
        0x7fc00000, 0x3f800000, /* nan, 1.000000 */ \
        0x3f800000, 0x7fc00000, /* 1.000000, nan */ \
        0x3f800000, 0x7fbfffff, /* 1.000000, nan */ \
        0x7fbfffff, 0x3f800000, /* nan, 1.000000 */ \
        0x3f800000, 0x7fbfffff, /* 1.000000, nan */ \
        0x7f800000, 0x7fc00000, /* inf, nan */ \
        0x7fc00000, 0x7f800000, /* nan, inf */ \
        0x7f800000, 0x7fbfffff, /* inf, nan */ \
        0x7fbfffff, 0x7f800000, /* nan, inf */ \
        0x3f800000, 0x7f800000, /* 1.000000, inf */ \
        0x3f800000, 0xff800000, /* 1.000000, -inf */ \
        0x7f800000, 0x3f800000, /* inf, 1.000000 */ \
        0xff800000, 0x3f800000, /* -inf, 1.000000 */ \
        0x3f800000, 0xbf800000, /* 1.000000, -1.000000 */ \
        0xbf800000, 0x3f800000 /* -1.000000, 1.000000 */) \
        push ARG1_64; \
        push ARG2_64; \
        movq xmm0, qword ptr [rsp + 8]; \
        movq xmm1, qword ptr [rsp]; \
        vcmpss xmm2, xmm1, xmm0, op; \
    TEST_END_64

MAKE_VCMPSS_TEST(0)
MAKE_VCMPSS_TEST(1)
MAKE_VCMPSS_TEST(2)
MAKE_VCMPSS_TEST(3)
MAKE_VCMPSS_TEST(4)
MAKE_VCMPSS_TEST(5)
MAKE_VCMPSS_TEST(6)
MAKE_VCMPSS_TEST(7)
MAKE_VCMPSS_TEST(8)
MAKE_VCMPSS_TEST(9)
MAKE_VCMPSS_TEST(10)
MAKE_VCMPSS_TEST(11)
MAKE_VCMPSS_TEST(12)
MAKE_VCMPSS_TEST(13)
MAKE_VCMPSS_TEST(14)
MAKE_VCMPSS_TEST(15)
MAKE_VCMPSS_TEST(16)
MAKE_VCMPSS_TEST(17)
MAKE_VCMPSS_TEST(18)
MAKE_VCMPSS_TEST(19)
MAKE_VCMPSS_TEST(20)
MAKE_VCMPSS_TEST(21)
MAKE_VCMPSS_TEST(22)
MAKE_VCMPSS_TEST(23)
MAKE_VCMPSS_TEST(24)
MAKE_VCMPSS_TEST(25)
MAKE_VCMPSS_TEST(26)
MAKE_VCMPSS_TEST(27)
MAKE_VCMPSS_TEST(28)
MAKE_VCMPSS_TEST(29)
MAKE_VCMPSS_TEST(30)
MAKE_VCMPSS_TEST(31)

#endif  // HAS_FEATURE_AVX
