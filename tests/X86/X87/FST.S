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

#define FST_INPUTS \
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
        0x3fd999999999999a,  /* 0.400000 */ \
        0x3fe3333333333333,  /* 0.600000 */ \
        0xbfd999999999999a,  /* -0.400000 */ \
        0xbfe3333333333333,  /* -0.600000 */ \
        0x4058ff5c28f5c28f,  /* 99.99 */ \
        0xc058ff5c28f5c28f)  /* -99.99 */

TEST_BEGIN_64(FSTm32, 1)
FST_INPUTS
    push ARG1_64
    fld QWORD PTR [rsp]
    lea rsp, [rsp - 8]
    fst DWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FSTm64, 1)
FST_INPUTS

    push ARG1_64
    fld QWORD PTR [rsp]
    lea rsp, [rsp - 8]
    fst QWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FSTst, 1)
FST_INPUTS

    push ARG1_64
    fld QWORD PTR [rsp]
    fld QWORD PTR [rsp]
    fsub st(1)
    fst st(1)
TEST_END_64


TEST_BEGIN_64(FSTPm32, 1)
FST_INPUTS

    push ARG1_64
    fld QWORD PTR [rsp]
    lea rsp, [rsp - 8]
    fstp DWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FSTPm64, 1)
FST_INPUTS

    push ARG1_64
    fld QWORD PTR [rsp]
    lea rsp, [rsp - 8]
    fstp QWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FSTPm80, 1)
TEST_INPUTS(0x0123456789ABCDEF)
    sub rsp, 16
    mov QWORD PTR [rsp], ARG1_64
    mov WORD PTR [rsp + 8], 0x1337
    fld TBYTE PTR [rsp]
    mov WORD PTR [rsp + 8], 0x0
    fstp TBYTE PTR [rsp]
    mov rax, QWORD PTR [rsp]
    movzx rbx, WORD PTR [rsp + 8]
    add rsp, 16
TEST_END_64

TEST_BEGIN_64(FSTPst, 1)
FST_INPUTS

    push ARG1_64
    fld QWORD PTR [rsp]
    fld QWORD PTR [rsp]
    fsub st(1)
    fstp st(1)
TEST_END_64

TEST_BEGIN_64(FISTm16, 1)
FST_INPUTS

    push ARG1_64
    fld QWORD PTR [rsp]
    lea rsp, [rsp - 8]
    fist WORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FISTm32, 1)
FST_INPUTS

    push ARG1_64
    fld QWORD PTR [rsp]
    lea rsp, [rsp - 8]
    fist DWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FISTPm16, 1)
FST_INPUTS

    push ARG1_64
    fld QWORD PTR [rsp]
    lea rsp, [rsp - 8]
    fistp WORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FISTPm32, 1)
FST_INPUTS

    push ARG1_64
    fld QWORD PTR [rsp]
    lea rsp, [rsp - 8]
    fistp DWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FISTPm64, 1)
FST_INPUTS

    push ARG1_64
    fld QWORD PTR [rsp]
    lea rsp, [rsp - 8]
    fistp QWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FISTTPm16, 1)
FST_INPUTS

    push ARG1_64
    fld QWORD PTR [rsp]
    lea rsp, [rsp - 8]
    fisttp WORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FISTTPm32, 1)
FST_INPUTS

    push ARG1_64
    fld QWORD PTR [rsp]
    lea rsp, [rsp - 8]
    fisttp DWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FISTTPm64, 1)
FST_INPUTS

    push ARG1_64
    fld QWORD PTR [rsp]
    lea rsp, [rsp - 8]
    fisttp QWORD PTR [rsp]
TEST_END_64
