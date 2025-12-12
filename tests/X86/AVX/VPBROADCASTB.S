/*
 * Copyright (c) 2019 Trail of Bits, Inc.
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
 #define VPBROADCASTB_INPUTS_64 \
      0x0000000000000000, 0x0000000000000000,  /* sanity check */\
      0xfedcba9876543210, 0x0000000000000000,  /* arbitrarily chosen values */\
      0xfedcba9876543210, 0xffffffffffffffff,  /* other arbitrarily chosen values */\
      0xfedcba9876543210, 0xaabbccddeeff1122   /* other arbitrarily chosen values */\

TEST_BEGIN_64(VPBROADCASTB_YMMqq_XMMb, 3)
TEST_INPUTS(VPBROADCASTB_INPUTS_64)
  movq xmm0, ARG1_64;
  vpbroadcastb ymm0, xmm0;
TEST_END_64

TEST_BEGIN_64(VBROADCASTBv128m8, 2)
TEST_INPUTS(VPBROADCASTB_INPUTS_64)
  push ARG1_64
  push ARG1_64
  movdqu xmm0, [rsp]
  push ARG2_64
  vpbroadcastb xmm0, BYTE ptr [rsp]
TEST_END_64

TEST_BEGIN_64(VPBROADCASTBv128v128, 2)
TEST_INPUTS(VPBROADCASTB_INPUTS_64)
  push ARG1_64
  push ARG1_64
  movdqu xmm0, [rsp]
  push ARG2_64
  push ARG2_64
  movdqu xmm1, [rsp]
  vpbroadcastb xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(VPBROADCASTSBv256m8, 2)
TEST_INPUTS(VPBROADCASTB_INPUTS_64)
  push ARG1_64
  push ARG1_64
  push ARG1_64
  push ARG1_64
  vmovdqu ymm0, [rsp]
  push ARG2_64
  vpbroadcastb ymm0, BYTE ptr [rsp]
TEST_END_64

TEST_BEGIN_64(VPBROADCASTBv256v128, 2)
TEST_INPUTS(VPBROADCASTB_INPUTS_64)
  push ARG1_64
  push ARG1_64
  push ARG1_64
  push ARG1_64
  vmovdqu ymm0, [rsp]
  push ARG2_64
  push ARG2_64
  movdqu xmm1, [rsp]
  vpbroadcastb ymm0, xmm1
TEST_END_64

TEST_BEGIN_64(VBROADCASTWv128m8, 2)
TEST_INPUTS(VPBROADCASTB_INPUTS_64)
  push ARG1_64
  push ARG1_64
  movdqu xmm0, [rsp]
  push ARG2_64
  vpbroadcastw xmm0, [rsp]
TEST_END_64

TEST_BEGIN_64(VPBROADCASTWv128v128, 2)
TEST_INPUTS(VPBROADCASTB_INPUTS_64)
  push ARG1_64
  push ARG1_64
  movdqu xmm0, [rsp]
  push ARG2_64
  push ARG2_64
  movdqu xmm1, [rsp]
  vpbroadcastw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(VPBROADCASTSWv256m16, 2)
TEST_INPUTS(VPBROADCASTB_INPUTS_64)
  push ARG1_64
  push ARG1_64
  push ARG1_64
  push ARG1_64
  vmovdqu ymm0, [rsp]
  push ARG2_64
  vpbroadcastw ymm0, [rsp]
TEST_END_64

TEST_BEGIN_64(VPBROADCASTWv256v128, 2)
TEST_INPUTS(VPBROADCASTB_INPUTS_64)
  push ARG1_64
  push ARG1_64
  push ARG1_64
  push ARG1_64
  vmovdqu ymm0, [rsp]
  push ARG2_64
  push ARG2_64
  movdqu xmm1, [rsp]
  vpbroadcastw ymm0, xmm1
TEST_END_64

TEST_BEGIN_64(VBROADCASTDv128m32, 2)
TEST_INPUTS(VPBROADCASTB_INPUTS_64)
  push ARG1_64
  push ARG1_64
  movdqu xmm0, [rsp]
  push ARG2_64
  vpbroadcastd xmm0, [rsp]
TEST_END_64

TEST_BEGIN_64(VPBROADCASTDv128v128, 2)
TEST_INPUTS(VPBROADCASTB_INPUTS_64)
  push ARG1_64
  push ARG1_64
  movdqu xmm0, [rsp]
  push ARG2_64
  push ARG2_64
  movdqu xmm1, [rsp]
  vpbroadcastd xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(VPBROADCASTSDv256m32, 2)
TEST_INPUTS(VPBROADCASTB_INPUTS_64)
  push ARG1_64
  push ARG1_64
  push ARG1_64
  push ARG1_64
  vmovdqu ymm0, [rsp]
  push ARG2_64
  vpbroadcastd ymm0, [rsp]
TEST_END_64

TEST_BEGIN_64(VPBROADCASTDv256v128, 2)
TEST_INPUTS(VPBROADCASTB_INPUTS_64)
  push ARG1_64
  push ARG1_64
  push ARG1_64
  push ARG1_64
  vmovdqu ymm0, [rsp]
  push ARG2_64
  push ARG2_64
  movdqu xmm1, [rsp]
  vpbroadcastd ymm0, xmm1
TEST_END_64

TEST_BEGIN_64(VBROADCASTQv128m64, 2)
TEST_INPUTS(VPBROADCASTB_INPUTS_64)
  push ARG1_64
  push ARG1_64
  movdqu xmm0, [rsp]
  push ARG2_64
  vpbroadcastq xmm0, [rsp]
TEST_END_64

TEST_BEGIN_64(VPBROADCASTQv128v128, 2)
TEST_INPUTS(VPBROADCASTB_INPUTS_64)
  push ARG1_64
  push ARG1_64
  movdqu xmm0, [rsp]
  push ARG2_64
  push ARG2_64
  movdqu xmm1, [rsp]
  vpbroadcastq xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(VPBROADCASTSQv256m64, 2)
TEST_INPUTS(VPBROADCASTB_INPUTS_64)
  push ARG1_64
  push ARG1_64
  push ARG1_64
  push ARG1_64
  vmovdqu ymm0, [rsp]
  push ARG2_64
  vpbroadcastq ymm0, [rsp]
TEST_END_64

TEST_BEGIN_64(VPBROADCASTQv256v128, 2)
TEST_INPUTS(VPBROADCASTB_INPUTS_64)
  push ARG1_64
  push ARG1_64
  push ARG1_64
  push ARG1_64
  vmovdqu ymm0, [rsp]
  push ARG2_64
  push ARG2_64
  movdqu xmm1, [rsp]
  vpbroadcastq ymm0, xmm1
TEST_END_64

TEST_BEGIN_64(VBROADCASTSSv128m32, 2)
TEST_INPUTS(VPBROADCASTB_INPUTS_64)
  push ARG1_64
  push ARG1_64
  movdqu xmm0, [rsp]
  push ARG2_64
  vbroadcastss xmm0, [rsp]
TEST_END_64

TEST_BEGIN_64(VBROADCASTSSv128v128, 2)
TEST_INPUTS(VPBROADCASTB_INPUTS_64)
  push ARG1_64
  push ARG1_64
  movdqu xmm0, [rsp]
  push ARG2_64
  push ARG2_64
  movdqu xmm1, [rsp]
  vbroadcastss xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(VBROADCASTSSv256m32, 2)
TEST_INPUTS(VPBROADCASTB_INPUTS_64)
  push ARG1_64
  push ARG1_64
  push ARG1_64
  push ARG1_64
  vmovdqu ymm0, [rsp]
  push ARG2_64
  vbroadcastss ymm0, [rsp]
TEST_END_64

TEST_BEGIN_64(VBROADCASTSSv256v128, 2)
TEST_INPUTS(VPBROADCASTB_INPUTS_64)
  push ARG1_64
  push ARG1_64
  push ARG1_64
  push ARG1_64
  vmovdqu ymm0, [rsp]
  push ARG2_64
  push ARG2_64
  movdqu xmm1, [rsp]
  vbroadcastss ymm0, xmm1
TEST_END_64

TEST_BEGIN_64(VBROADCASTSDv256m64, 2)
TEST_INPUTS(VPBROADCASTB_INPUTS_64)
  push ARG1_64
  push ARG1_64
  push ARG1_64
  push ARG1_64
  vmovdqu ymm0, [rsp]
  push ARG2_64
  vbroadcastsd ymm0, [rsp]
TEST_END_64

TEST_BEGIN_64(VBROADCASTSDv256v128, 2)
TEST_INPUTS(VPBROADCASTB_INPUTS_64)
  push ARG1_64
  push ARG1_64
  push ARG1_64
  push ARG1_64
  vmovdqu ymm0, [rsp]
  push ARG2_64
  push ARG2_64
  movdqu xmm1, [rsp]
  vbroadcastsd ymm0, xmm1
TEST_END_64

TEST_BEGIN_64(VBROADCASTF128v256m128, 2)
TEST_INPUTS(VPBROADCASTB_INPUTS_64)
  push ARG1_64
  push ARG1_64
  push ARG1_64
  push ARG1_64
  vmovdqu ymm0, [rsp]
  push ARG2_64
  push ARG2_64
  vbroadcastf128 ymm0, [rsp]
TEST_END_64

TEST_BEGIN_64(VBROADCASTI128v256m128, 2)
TEST_INPUTS(VPBROADCASTB_INPUTS_64)
  push ARG1_64
  push ARG1_64
  push ARG1_64
  push ARG1_64
  vmovdqu ymm0, [rsp]
  push ARG2_64
  push ARG2_64
  vbroadcasti128 ymm0, [rsp]
TEST_END_64

#endif  // HAS_FEATURE_AVX
