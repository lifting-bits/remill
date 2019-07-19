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

TEST_BEGIN_64(MOVBE_GPRv_MEMv_16,  1)
TEST_INPUTS(
    0x41ec)
    push ARG1_64
    movbe ax, [rsp]
TEST_END_64

TEST_BEGIN_64(MOVBE_GPRv_MEMv_32, 1)
TEST_INPUTS(
    0x41ec0806)
    push ARG1_64
    movbe eax, [rsp]
TEST_END_64

TEST_BEGIN_64(MOVBE_GPRv_MEMv_64, 1)
TEST_INPUTS(
    0x41ec080600)
    push ARG1_64
    movbe rax, [rsp]
TEST_END_64
