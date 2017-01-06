/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN_64(FADDst1, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    fadd st(1)
TEST_END_64

TEST_BEGIN_64(FADDm64, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fadd QWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FADDm32, 2)
TEST_INPUTS(TEST_INPUTS_MMX_DWORD)
    push ARG1_64
    fld DWORD PTR [rsp]
    push ARG2_64
    fadd DWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FADDP, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    faddp
TEST_END_64

TEST_BEGIN_64(FADDPst1, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    faddp st(1)
TEST_END_64

TEST_BEGIN_64(FIADDm16, 2)
TEST_INPUTS(TEST_INPUTS_MMX_DWORD)
    push ARG1_64
    fld DWORD PTR [rsp]
    push ARG2_64
    fiadd WORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FIADDm32, 2)
TEST_INPUTS(TEST_INPUTS_MMX_DWORD)
    push ARG1_64
    fld DWORD PTR [rsp]
    push ARG2_64
    fiadd DWORD PTR [rsp]
TEST_END_64
