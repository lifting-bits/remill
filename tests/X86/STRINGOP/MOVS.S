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

TEST_BEGIN(MOVSB, 1)
TEST_INPUTS(0)
#ifdef IN_TEST_GENERATOR
    .byte IF_64_BIT(0x48, ) 0x8d, 0x7c, 0x24, 0xf8
    .byte IF_64_BIT(0x48, ) 0x8d, 0x74, 0x24, 0xf8
#else
    lea rdi, [rsp - 8]
    lea rsi, [rsp - 8]
#endif
    .byte 0xa4
TEST_END

TEST_BEGIN(MOVSW, 1)
TEST_INPUTS(0)
#ifdef IN_TEST_GENERATOR
    .byte IF_64_BIT(0x48, ) 0x8d, 0x7c, 0x24, 0xf8
    .byte IF_64_BIT(0x48, ) 0x8d, 0x74, 0x24, 0xf8
#else
    lea rdi, [rsp - 8]
    lea rsi, [rsp - 8]
#endif
    .byte 0x66, 0xa5
TEST_END

TEST_BEGIN(MOVSD, 1)
TEST_INPUTS(0)
#ifdef IN_TEST_GENERATOR
    .byte IF_64_BIT(0x48, ) 0x8d, 0x7c, 0x24, 0xf8
    .byte IF_64_BIT(0x48, ) 0x8d, 0x74, 0x24, 0xf8
#else
    lea rdi, [rsp - 8]
    lea rsi, [rsp - 8]
#endif
    .byte 0xa5
TEST_END

TEST_BEGIN_64(MOVSQ_64, 1)
TEST_INPUTS(0)
    lea rdi, [rsp - 8]
    lea rsi, [rsp - 8]
    .byte 0x48, 0xa5
TEST_END_64
