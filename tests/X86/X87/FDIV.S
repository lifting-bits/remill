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

TEST_BEGIN_64(FDIVst1, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    fdiv st(1)
TEST_END_64

TEST_BEGIN_64(FDIVm64, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fdiv QWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FDIVm32, 2)
TEST_INPUTS(TEST_INPUTS_MMX_DWORD)
    push ARG1_64
    fld DWORD PTR [rsp]
    push ARG2_64
    fdiv DWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FDIVP, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    fdivp
TEST_END_64

TEST_BEGIN_64(FDIVPst1, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    fdivp st(1)
TEST_END_64

TEST_BEGIN_64(FDIVRst1, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    fdivr st(1)
TEST_END_64

TEST_BEGIN_64(FDIVRm64, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fdivr QWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FDIVRm32, 2)
TEST_INPUTS(TEST_INPUTS_MMX_DWORD)
    push ARG1_64
    fld DWORD PTR [rsp]
    push ARG2_64
    fdivr DWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FDIVRP, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    fdivrp
TEST_END_64

TEST_BEGIN_64(FDIVRPst1, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    fdivrp st(1)
TEST_END_64

TEST_BEGIN_64(FIDIVm16, 2)
TEST_INPUTS(TEST_INPUTS_MMX_DWORD)
    push ARG1_64
    fld DWORD PTR [rsp]
    push ARG2_64
    fidiv WORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FIDIVm32, 2)
TEST_INPUTS(TEST_INPUTS_MMX_DWORD)
    push ARG1_64
    fld DWORD PTR [rsp]
    push ARG2_64
    fidiv DWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FIDIVRm16, 2)
TEST_INPUTS(TEST_INPUTS_MMX_DWORD)
    push ARG1_64
    fld DWORD PTR [rsp]
    push ARG2_64
    fidivr WORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FIDIVRm32, 2)
TEST_INPUTS(TEST_INPUTS_MMX_DWORD)
    push ARG1_64
    fld DWORD PTR [rsp]
    push ARG2_64
    fidivr DWORD PTR [rsp]
TEST_END_64


