/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN_64(FMULst1, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    fmul st(1)
TEST_END_64

TEST_BEGIN_64(FMULm64, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fmul QWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FMULm32, 2)
TEST_INPUTS(TEST_INPUTS_MMX_DWORD)
    push ARG1_64
    fld DWORD PTR [rsp]
    push ARG2_64
    fmul DWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FMULP, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    fmulp
TEST_END_64

TEST_BEGIN_64(FMULPst1, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    fmulp st(1)
TEST_END_64

TEST_BEGIN_64(FIMULm16, 2)
TEST_INPUTS(TEST_INPUTS_MMX_DWORD)
    push ARG1_64
    fld DWORD PTR [rsp]
    push ARG2_64
    fimul WORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FIMULm32, 2)
TEST_INPUTS(TEST_INPUTS_MMX_DWORD)
    push ARG1_64
    fld DWORD PTR [rsp]
    push ARG2_64
    fimul DWORD PTR [rsp]
TEST_END_64



