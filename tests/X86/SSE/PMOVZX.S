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

TEST_BEGIN_64(PMOXZXBWv128v128, 1)
TEST_INPUTS(0)
     pmovzxbw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PMOXZXBWv128m64, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     pmovzxbw xmm0, [rsp]
TEST_END_64

#if HAS_FEATURE_AVX
TEST_BEGIN_64(VPMOXZXBWv128v128, 1)
TEST_INPUTS(0)
     vpmovzxbw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(VPMOXZXBWv128m64, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     vpmovzxbw xmm0, [rsp]
TEST_END_64

TEST_BEGIN_64(VPMOXZXBWv256v256, 1)
TEST_INPUTS(0)
     vpmovzxbw ymm0, xmm4
TEST_END_64

TEST_BEGIN_64(VPMOXZXBWv256m128, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     push ARG1_64
     vpmovzxbw ymm0, [rsp]
TEST_END_64

#endif  // HAS_FEATURE_AVX

TEST_BEGIN_64(PMOXZXBDv128v128, 1)
TEST_INPUTS(0)
     pmovzxbd xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PMOXZXBDv128m32, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     pmovzxbd xmm0, [rsp]
TEST_END_64

#if HAS_FEATURE_AVX
TEST_BEGIN_64(VPMOXZXBDv128v128, 1)
TEST_INPUTS(0)
     vpmovzxbd xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(VPMOXZXBDv128m32, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     vpmovzxbd xmm0, [rsp]
TEST_END_64

TEST_BEGIN_64(VPMOXZXBDv256v256, 1)
TEST_INPUTS(0)
     vpmovzxbd ymm0, xmm4
TEST_END_64

TEST_BEGIN_64(VPMOXZXBDv256m64, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     vpmovzxbd ymm0, [rsp]
TEST_END_64

#endif  // HAS_FEATURE_AVX

TEST_BEGIN_64(PMOXZXBQv128v128, 1)
TEST_INPUTS(0)
     pmovzxbq xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PMOXZXBQv128m16, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     pmovzxbq xmm0, [rsp]
TEST_END_64

#if HAS_FEATURE_AVX
TEST_BEGIN_64(VPMOXZXBQv128v128, 1)
TEST_INPUTS(0)
     vpmovzxbq xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(VPMOXZXBQv128m16, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     vpmovzxbq xmm0, [rsp]
TEST_END_64

TEST_BEGIN_64(VPMOXZXBQv256v256, 1)
TEST_INPUTS(0)
     vpmovzxbq ymm0, xmm4
TEST_END_64

TEST_BEGIN_64(VPMOXZXBQv256m32, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     vpmovzxbq ymm0, [rsp]
TEST_END_64

#endif  // HAS_FEATURE_AVX

TEST_BEGIN_64(PMOXZXWDv128v128, 1)
TEST_INPUTS(0)
     pmovzxwd xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PMOXZXWDv128m64, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     pmovzxwd xmm0, [rsp]
TEST_END_64

#if HAS_FEATURE_AVX
TEST_BEGIN_64(VPMOXZXWDv128v128, 1)
TEST_INPUTS(0)
     vpmovzxwd xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(VPMOXZXWDv128m64, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     vpmovzxwd xmm0, [rsp]
TEST_END_64

TEST_BEGIN_64(VPMOXZXWDv256v256, 1)
TEST_INPUTS(0)
     vpmovzxwd ymm0, xmm4
TEST_END_64

TEST_BEGIN_64(VPMOXZXWDv256m128, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     push ARG1_64
     vpmovzxwd ymm0, [rsp]
TEST_END_64

#endif  // HAS_FEATURE_AVX

TEST_BEGIN_64(PMOXZXWQv128v128, 1)
TEST_INPUTS(0)
     pmovzxwq xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PMOXZXWQv128m32, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     pmovzxwq xmm0, [rsp]
TEST_END_64

#if HAS_FEATURE_AVX
TEST_BEGIN_64(VPMOXZXWQv128v128, 1)
TEST_INPUTS(0)
     vpmovzxwq xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(VPMOXZXWQv128m32, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     vpmovzxwq xmm0, [rsp]
TEST_END_64

TEST_BEGIN_64(VPMOXZXWQv256v256, 1)
TEST_INPUTS(0)
     vpmovzxwq ymm0, xmm4
TEST_END_64

TEST_BEGIN_64(VPMOXZXWQv256m64, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     vpmovzxwq ymm0, [rsp]
TEST_END_64

#endif  // HAS_FEATURE_AVX

TEST_BEGIN_64(PMOXZXDQv128v128, 1)
TEST_INPUTS(0)
     pmovzxdq xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PMOXZXDQv128m64, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     pmovzxdq xmm0, [rsp]
TEST_END_64

#if HAS_FEATURE_AVX
TEST_BEGIN_64(VPMOXZXDQv128v128, 1)
TEST_INPUTS(0)
     vpmovzxdq xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(VPMOXZXDQv128m64, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     vpmovzxdq xmm0, [rsp]
TEST_END_64

TEST_BEGIN_64(VPMOXZXDQv256v256, 1)
TEST_INPUTS(0)
     vpmovzxdq ymm0, xmm4
TEST_END_64

TEST_BEGIN_64(VPMOXZXDQv256m128, 1)
TEST_INPUTS(0xaabbccddeeff11)
     push ARG1_64
     push ARG1_64
     vpmovzxdq ymm0, [rsp]
TEST_END_64

#endif  // HAS_FEATURE_AVX