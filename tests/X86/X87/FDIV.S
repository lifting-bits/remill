/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

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


