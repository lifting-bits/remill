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

TEST_BEGIN(CPUID, 2)
TEST_INPUTS(
    0x07, 0,
    0x05, 0,
    0x0A, 0,
    0x0B, 0,
    0x0C, 0,
    0x80000008, 0,
    0x0D, 0,
    0x0D, 1,
    0x0D, 31,
    0x0D, 32,
    0x0D, 63)

    mov eax, ARG1_32
    mov ecx, ARG2_32
    cpuid
TEST_END
