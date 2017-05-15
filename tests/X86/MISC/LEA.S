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

TEST_BEGIN_MEM(LEA, 3)
TEST_INPUTS(
    0, 0, 0,
    0xFF, 0xFF, 0xFF,
    0xFF, 0, 0xFF,
    0xFF, 0xFF, 0)
    // lea ARG1_32, [ARG2_32 + 2 * ARG3_32 + 1]
    .byte IF_64_BIT(0x67,) 0x8D, 0x7C, 0x56, 0x01 ;
TEST_END_MEM

TEST_BEGIN_MEM_64(LEA_64, 3)
TEST_INPUTS(
    0, 0, 0,
    0xFF, 0xFF, 0xFF,
    0xFF, 0, 0xFF,
    0xFF, 0xFF, 0)
    lea ARG1_64, [ARG2_64 + 2 * ARG3_64 + 1]
TEST_END_MEM_64
