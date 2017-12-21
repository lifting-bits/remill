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

#define VFMADDSD_INPUTS_64                                             \
    0.0, 0.0, 0.0,    /* will evaluate to 0.0 */                       \
    1.0, 1.0, 1.0,    /* will evaluate to 2.0 */                       \
    2.0, 3.0, 4.0,    /* will evaluate to 10.0, 11.0, or 14.0 */       \
    2.5, 2.5, 2.5,    /* will evaluate to exactly 8.75 */              \
    1.75, 1.5, -2.25, /* test with negative values */                  \
    1.2, 2.3, 3.4,    /* test floating point rounding accuracy */      \
    0xc000000000000000, 0xc000000000000000, 0xc000000000000000, /* -2.0, -2.0, -2.0 */  \
    0x3FF0000000000000, 1.0, 0xBFF0000000000000,                /* 1.0, 1.0, -1.0 */    \
    0xbffe000000000000, 1.0, 0xc000000000000000,                /* -1.875, 1.0, -2.0 */ \
    1.0, 0x7ff8000000000000, 0x7ff8000000000000,                /* 1.0, QNaN, QNaN */   \
    0xfff8000000000001, 1.0, 0xfff8000000000001,                /* -QNaN, 1.0, -QNaN */ \
    0x7ff0000000000001, 1.0, 0x7ff0000000000001,                /* SNaN, 1.0, SNaN */   \
    0xfff0000000000001, 1.0, 0xfff0000000000001,                /* -SNaN, 1.0, -SNaN */ \
    0x7ff0000000000000, 1.0, 0x7ff0000000000000,                /* inf, 1.0, inf */     \
    0x7ff0000000000000, 1.0, 0xfff0000000000000,                /* inf, 1.0, -inf */    \
    0x8000000000000000, 1.0, 0x8000000000000000                 /* -0, 1.0, -0 */

TEST_BEGIN_64(VFMADD132SDv128v128m64, 3)
TEST_INPUTS(VFMADDSD_INPUTS_64)
    movq xmm0, ARG1_64;
    movq xmm1, ARG2_64;
    push ARG3_64;
    vfmadd132sd xmm0, xmm1, qword ptr [rsp];
TEST_END_64

TEST_BEGIN_64(VFMADD132SDv128v128v128, 3)
TEST_INPUTS(VFMADDSD_INPUTS_64)
    movq xmm0, ARG1_64;
    movq xmm1, ARG2_64;
    movq xmm2, ARG3_64;
    vfmadd132sd xmm0, xmm1, xmm2;
TEST_END_64

TEST_BEGIN_64(VFMADD213SDv128v128m64, 3)
TEST_INPUTS(VFMADDSD_INPUTS_64)
    movq xmm0, ARG1_64;
    movq xmm1, ARG2_64;
    push ARG3_64;
    vfmadd213sd xmm0, xmm1, qword ptr [rsp];
TEST_END_64

TEST_BEGIN_64(VFMADD213SDv128v128v128, 3)
TEST_INPUTS(VFMADDSD_INPUTS_64)
    movq xmm0, ARG1_64;
    movq xmm1, ARG2_64;
    movq xmm2, ARG3_64;
    vfmadd213sd xmm0, xmm1, xmm2;
TEST_END_64

TEST_BEGIN_64(VFMADD231SDv128v128m64, 3)
TEST_INPUTS(VFMADDSD_INPUTS_64)
    movq xmm0, ARG1_64;
    movq xmm1, ARG2_64;
    push ARG3_64;
    vfmadd231sd xmm0, xmm1, qword ptr [rsp];
TEST_END_64

TEST_BEGIN_64(VFMADD231SDv128v128v128, 3)
TEST_INPUTS(VFMADDSD_INPUTS_64)
    movq xmm0, ARG1_64;
    movq xmm1, ARG2_64;
    movq xmm2, ARG3_64;
    vfmadd231sd xmm0, xmm1, xmm2;
TEST_END_64

#endif  // HAS_FEATURE_AVX