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

TEST_BEGIN_64(CDQE_64, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0x80,
    0x7F00,
    0x8000,
    0xFF00,
    0xFF00FF00,
    0x00FF00FF,
    0x7F00FF00,
    0x80FF00FF,
    0xFFFFFFFF00000000,
    0xFFFFFFF080000000)
    mov rax, ARG1_64
    cdqe
TEST_END_64
