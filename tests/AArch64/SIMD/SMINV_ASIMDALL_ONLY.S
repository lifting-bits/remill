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

TEST_BEGIN(SMINV_ASIMDALL_ONLY_8B, sminv_v8b, 1)
TEST_INPUTS(0)
    sminv b5, v0.8b
    sminv b6, v1.8b
    sminv b7, v2.8b
    sminv b8, v3.8b
TEST_END

TEST_BEGIN(SMINV_ASIMDALL_ONLY_16B, sminv_v16b, 1)
TEST_INPUTS(0)
    sminv b5, v0.16b
    sminv b6, v1.16b
    sminv b7, v2.16b
    sminv b8, v3.16b
TEST_END

TEST_BEGIN(SMINV_ASIMDALL_ONLY_4H, sminv_v4h, 1)
TEST_INPUTS(0)
    sminv h5, v0.4h
    sminv h6, v1.4h
    sminv h7, v2.4h
    sminv h8, v3.4h
TEST_END

TEST_BEGIN(SMINV_ASIMDALL_ONLY_8H, sminv_v8h, 1)
TEST_INPUTS(0)
    sminv h5, v0.8h
    sminv h6, v1.8h
    sminv h7, v2.8h
    sminv h8, v3.8h
TEST_END

TEST_BEGIN(SMINV_ASIMDALL_ONLY_4S, sminv_v4s, 1)
TEST_INPUTS(0)
    sminv s5, v0.4s
    sminv s6, v1.4s
    sminv s7, v2.4s
    sminv s8, v3.4s
TEST_END
