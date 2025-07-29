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

TEST_BEGIN_64(PMOVSXBWv128v128, 1)
TEST_INPUTS(0)
     pmovsxbw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PMOVSXBWv128m64, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     pmovsxbw xmm0, [rsp]
TEST_END_64

#if HAS_FEATURE_AVX
TEST_BEGIN_64(VPMOVSXBWv128v128, 1)
TEST_INPUTS(0)
     vpmovsxbw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(VPMOVSXBWv128m64, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     vpmovsxbw xmm0, [rsp]
TEST_END_64

TEST_BEGIN_64(VPMOVSXBWv256v256, 1)
TEST_INPUTS(0)
     vpmovsxbw ymm0, xmm4
TEST_END_64

TEST_BEGIN_64(VPMOVSXBWv256m128, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     push ARG1_64
     vpmovsxbw ymm0, [rsp]
TEST_END_64

#endif  // HAS_FEATURE_AVX

TEST_BEGIN_64(PMOVSXBDv128v128, 1)
TEST_INPUTS(0)
     pmovsxbd xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PMOVSXBDv128m32, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     pmovsxbd xmm0, [rsp]
TEST_END_64

#if HAS_FEATURE_AVX
TEST_BEGIN_64(VPMOVSXBDv128v128, 1)
TEST_INPUTS(0)
     vpmovsxbd xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(VPMOVSXBDv128m32, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     vpmovsxbd xmm0, [rsp]
TEST_END_64

TEST_BEGIN_64(VPMOVSXBDv256v256, 1)
TEST_INPUTS(0)
     vpmovsxbd ymm0, xmm4
TEST_END_64

TEST_BEGIN_64(VPMOVSXBDv256m64, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     vpmovsxbd ymm0, [rsp]
TEST_END_64

#endif  // HAS_FEATURE_AVX

TEST_BEGIN_64(PMOVSXBQv128v128, 1)
TEST_INPUTS(0)
     pmovsxbq xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PMOVSXBQv128m16, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     pmovsxbq xmm0, [rsp]
TEST_END_64

#if HAS_FEATURE_AVX
TEST_BEGIN_64(VPMOVSXBQv128v128, 1)
TEST_INPUTS(0)
     vpmovsxbq xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(VPMOVSXBQv128m16, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     vpmovsxbq xmm0, [rsp]
TEST_END_64

TEST_BEGIN_64(VPMOVSXBQv256v256, 1)
TEST_INPUTS(0)
     vpmovsxbq ymm0, xmm4
TEST_END_64

TEST_BEGIN_64(VPMOVSXBQv256m32, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     vpmovsxbq ymm0, [rsp]
TEST_END_64

#endif  // HAS_FEATURE_AVX

TEST_BEGIN_64(PMOVSXWDv128v128, 1)
TEST_INPUTS(0)
     pmovsxwd xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PMOVSXWDv128m64, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     pmovsxwd xmm0, [rsp]
TEST_END_64

#if HAS_FEATURE_AVX
TEST_BEGIN_64(VPMOVSXWDv128v128, 1)
TEST_INPUTS(0)
     vpmovsxwd xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(VPMOVSXWDv128m64, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     vpmovsxwd xmm0, [rsp]
TEST_END_64

TEST_BEGIN_64(VPMOVSXWDv256v256, 1)
TEST_INPUTS(0)
     vpmovsxwd ymm0, xmm4
TEST_END_64

TEST_BEGIN_64(VPMOVSXWDv256m128, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     push ARG1_64
     vpmovsxwd ymm0, [rsp]
TEST_END_64

#endif  // HAS_FEATURE_AVX

TEST_BEGIN_64(PMOVSXWQv128v128, 1)
TEST_INPUTS(0)
     pmovsxwq xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PMOVSXWQv128m32, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     pmovsxwq xmm0, [rsp]
TEST_END_64

#if HAS_FEATURE_AVX
TEST_BEGIN_64(VPMOVSXWQv128v128, 1)
TEST_INPUTS(0)
     vpmovsxwq xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(VPMOVSXWQv128m32, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     vpmovsxwq xmm0, [rsp]
TEST_END_64

TEST_BEGIN_64(VPMOVSXWQv256v256, 1)
TEST_INPUTS(0)
     vpmovsxwq ymm0, xmm4
TEST_END_64

TEST_BEGIN_64(VPMOVSXWQv256m64, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     vpmovsxwq ymm0, [rsp]
TEST_END_64

#endif  // HAS_FEATURE_AVX

TEST_BEGIN_64(PMOVSXDQv128v128, 1)
TEST_INPUTS(0)
     pmovsxdq xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PMOVSXDQv128m64, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     pmovsxdq xmm0, [rsp]
TEST_END_64

#if HAS_FEATURE_AVX
TEST_BEGIN_64(VPMOVSXDQv128v128, 1)
TEST_INPUTS(0)
     vpmovsxdq xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(VPMOVSXDQv128m64, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     vpmovsxdq xmm0, [rsp]
TEST_END_64

TEST_BEGIN_64(VPMOVSXDQv256v256, 1)
TEST_INPUTS(0)
     vpmovsxdq ymm0, xmm4
TEST_END_64

TEST_BEGIN_64(VPMOVSXDQv256m128, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     push ARG1_64
     vpmovsxdq ymm0, [rsp]
TEST_END_64

#endif  // HAS_FEATURE_AVX