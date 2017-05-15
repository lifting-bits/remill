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

TEST_BEGIN_64(CVTSD2SSv128m64, 1)
TEST_INPUTS(
    0x401199999999999a,  /* 4.4 */
    0x4012000000000000,  /* 4.5 */
    0x4012666666666666,  /* 4.6 */
    0x7ff0000000000000,  /* +inf */
    0xfff0000000000000,  /* -inf */
    0xfff8000000000000,  /* -nan */
    0x7ff8000000000000)  /* nan */

    push ARG1_64
    cvtsd2ss xmm0, QWORD PTR [rsp]
TEST_END_64

TEST_BEGIN(CVTSD2SSv128v128, 1)
TEST_INPUTS(0)
    cvtsd2ss xmm0, xmm1
    cvtsd2ss xmm1, xmm2
    cvtsd2ss xmm2, xmm3
    cvtsd2ss xmm3, xmm4
TEST_END

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VCVTSD2SSv128v128m64, 1)
TEST_INPUTS(
    0x401199999999999a,  /* 4.4 */
    0x4012000000000000,  /* 4.5 */
    0x4012666666666666,  /* 4.6 */
    0x7ff0000000000000,  /* +inf */
    0xfff0000000000000,  /* -inf */
    0xfff8000000000000,  /* -nan */
    0x7ff8000000000000)  /* nan */

    push ARG1_64
    vcvtsd2ss xmm0, xmm1, QWORD PTR [rsp]
TEST_END_64

TEST_BEGIN(VCVTSD2SSv128v128v128, 1)
TEST_INPUTS(0)
    vcvtsd2ss xmm0, xmm1, xmm2
    vcvtsd2ss xmm1, xmm2, xmm3
    vcvtsd2ss xmm2, xmm3, xmm4
    vcvtsd2ss xmm3, xmm4, xmm5
TEST_END

#endif  // HAS_FEATURE_AVX
