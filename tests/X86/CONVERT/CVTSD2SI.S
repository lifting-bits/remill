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

#define CVTSD2SI_INPUTS \
    TEST_INPUTS( \
        0x7ff0000000000000,  /* +inf */ \
        0xfff0000000000000,  /* -inf */ \
        0x10000000000000,  /* std::numeric_limits<double>::min() */ \
        0x7fefffffffffffff,  /* std::numeric_limits<double>::max() */ \
        0x0,  /* 0 */ \
        0x3fe0000000000000,  /* 0.5 */ \
        0xbfe0000000000000,  /* -0.5 */ \
        0x3ff0000000000000,  /* 1.0 */ \
        0xbff0000000000000,  /* -1.0 */ \
        0x4058ff5c28f5c28f,  /* 99.99 */ \
        0xc058ff5c28f5c28f)  /* -99.99 */

TEST_BEGIN_64(CVTSD2SIr32m64, 1)
CVTSD2SI_INPUTS

    mov QWORD PTR [rsp - 8], ARG1_64
    cvtsd2si eax, QWORD PTR [rsp - 8]
TEST_END_64

TEST_BEGIN_64(CVTSD2SIr32v128, 1)
CVTSD2SI_INPUTS

    movq xmm0, ARG1_64
    cvtsd2si eax, xmm0
TEST_END_64

TEST_BEGIN_64(CVTSD2SIr64m64, 1)
CVTSD2SI_INPUTS

    mov QWORD PTR [rsp - 8], ARG1_64
    cvtsd2si rax, QWORD PTR [rsp - 8]
TEST_END_64

TEST_BEGIN_64(CVTSD2SIr64v128, 1)
CVTSD2SI_INPUTS

    movq xmm0, ARG1_64
    cvtsd2si rax, xmm0
TEST_END_64
