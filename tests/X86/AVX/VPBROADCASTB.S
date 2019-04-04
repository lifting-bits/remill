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
      0xfedcba9876543210, 0xffffffffffffffff   /* other arbitrarily chosen values */\

TEST_BEGIN_64(VPBROADCASTB_YMMqq_XMMb, 3)
TEST_INPUTS(VPBROADCASTB_INPUTS_64)
  movq xmm0, ARG1_64;
  vpbroadcastb ymm0, xmm0;
TEST_END_64

#endif  // HAS_FEATURE_AVX
