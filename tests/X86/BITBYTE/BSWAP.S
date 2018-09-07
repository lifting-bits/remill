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

TEST_BEGIN(BSWAPr16, 1)
TEST_INPUTS(
    0,
    1,
    0x01609B27,
    0xDE39D6C5,
    0x6818FB14,
    0xED70DFD2,
    0x21406ECA,
    0xAABBCCDD)

    mov eax, ARG1_32
    .byte 0x66, 0x0f, 0xc8
TEST_END

TEST_BEGIN_64(BSWAPr16_amd64, 1)
TEST_INPUTS(
    0,
    1,
    0x01609B27,
    0xDE39D6C5,
    0x6818FB14,
    0xED70DFD2,
    0x21406ECA,
    0xAABBCCDD)

    mov rax, ARG1_64
    .byte 0x66, 0x0f, 0xc8
TEST_END_64

TEST_BEGIN(BSWAPr32, 1)
TEST_INPUTS(
    0,
    1,
    0x80000000,
    0x80000001,
    0xFFFFFFFF,
    0x00000080,
    0x08000000,
    0xAABBCCDD)

    bswap ARG1_32
TEST_END

TEST_BEGIN_64(BSWAPr64, 1)
TEST_INPUTS(
    0,
    1,
    0x80000000,
    0x80000001,
    0xFFFFFFFF,
    0x00000080,
    0x08000000,
    0xAABBCCDD)

    bswap ARG1_64
TEST_END_64
