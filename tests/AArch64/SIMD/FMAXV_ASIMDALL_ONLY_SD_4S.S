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

TEST_BEGIN(FMAXV_ASIMDALL_ONLY_SD_4S, fmaxv_v4s, 1)
TEST_INPUTS(0)
    fmaxv s5, v0.4s
    fmaxv s6, v1.4s
    fmaxv s7, v2.4s
    fmaxv s8, v3.4s
TEST_END
