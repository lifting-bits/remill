/*
 * Copyright (c) 2021 Trail of Bits, Inc.
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

#if HAS_FEATURE_AVX512
TEST_BEGIN_64(KMOVW_MASKmskw_GPR32u32_AVX512, 1)
TEST_INPUTS(
    0,
    1,
    0x41,
    0xff,
    0x80)

    kmovw k2, ARG1_32
TEST_END_64


TEST_BEGIN_64(KMOVW_MASKmskw_MASKu16_AVX512, 1)
TEST_INPUTS(
    0,
    1,
    0x41,
    0xff,
    0x80)

    kmovw k2, ARG1_32
    kmovw k2, k1
TEST_END_64

TEST_BEGIN_64(KMOVW_GPR32u32_MASKmskw_AVX512, 1)
TEST_INPUTS(
    0,
    1,
    0x41,
    0xff,
    0x80)

    kmovw k2, ARG1_32
    kmovw RET_32, k2
TEST_END_64

#endif  // HAS_FEATURE_AVX512s