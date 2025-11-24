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

TEST_BEGIN_64(FLDm32, 1)
TEST_INPUTS(TEST_INPUTS_MMX_DWORD)
    push ARG1_64
    fld DWORD PTR [rsp]
TEST_END_64


TEST_BEGIN_64(FLDm64, 1)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FLDm80, 1)
TEST_INPUTS(0x0123456789ABCDEF)
    sub rsp, 16
    mov QWORD PTR [rsp], ARG1_64
    mov WORD PTR [rsp + 8], 0x1337
    fld TBYTE PTR [rsp]
    add rsp, 16
TEST_END_64

TEST_BEGIN_64(FLDst0, 1)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    fld st(0)
TEST_END_64

TEST_BEGIN_64(FLDst1, 1)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    fld QWORD PTR [rsp]
    fld st(1)
TEST_END_64

TEST_BEGIN(FLD1_ST0, 1)
TEST_INPUTS(0)
    fld1
TEST_END

TEST_BEGIN(FLD2T_ST0, 1)
TEST_INPUTS(0)
    fldl2t
TEST_END

TEST_BEGIN(FLD2E_ST0, 1)
TEST_INPUTS(0)
    fldl2e
TEST_END

TEST_BEGIN(FLDPI_ST0, 1)
TEST_INPUTS(0)
    fldpi
TEST_END

TEST_BEGIN(FLDLG2_ST0, 1)
TEST_INPUTS(0)
    fldlg2
TEST_END

TEST_BEGIN(FLDLN2_ST0, 1)
TEST_INPUTS(0)
    fldln2
TEST_END

TEST_BEGIN(FLDZ_ST0, 1)
TEST_INPUTS(0)
    fldz
TEST_END

TEST_BEGIN_64(FILDm16, 1)
TEST_INPUTS(
    0,
    0xFFFFFFFFFFFFFFFF,
    0x4141414141414141,
    0x8181818181818181)
    push ARG1_64
    fild WORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FILDm32, 1)
TEST_INPUTS(
    0,
    0xFFFFFFFFFFFFFFFF,
    0x4141414141414141,
    0x8181818181818181)
    push ARG1_64
    fild DWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FILDm64, 1)
TEST_INPUTS(
    0,
    0xFFFFFFFFFFFFFFFF,
    0x4141414141414141,
    0x8181818181818181)
    push ARG1_64
    fild QWORD PTR [rsp]
TEST_END_64
