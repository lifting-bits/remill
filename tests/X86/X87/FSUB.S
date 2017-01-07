/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN_64(FSUBst1, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    fsub st(1)
TEST_END_64

TEST_BEGIN_64(FSUBm64, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fsub QWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FSUBm32, 2)
TEST_INPUTS(TEST_INPUTS_MMX_DWORD)
    push ARG1_64
    fld DWORD PTR [rsp]
    push ARG2_64
    fsub DWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FSUBP, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    fsubp
TEST_END_64

TEST_BEGIN_64(FSUBPst1, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    fsubp st(1)
TEST_END_64

TEST_BEGIN_64(FSUBRst1, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    fsubr st(1)
TEST_END_64

TEST_BEGIN_64(FSUBRm64, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fsubr QWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FSUBRm32, 2)
TEST_INPUTS(TEST_INPUTS_MMX_DWORD)
    push ARG1_64
    fld DWORD PTR [rsp]
    push ARG2_64
    fsubr DWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FSUBRP, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    fsubrp
TEST_END_64

TEST_BEGIN_64(FSUBRPst1, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    fsubrp st(1)
TEST_END_64

TEST_BEGIN_64(FISUBm16, 2)
TEST_INPUTS(TEST_INPUTS_MMX_DWORD)
    push ARG1_64
    fld DWORD PTR [rsp]
    push ARG2_64
    fisub WORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FISUBm32, 2)
TEST_INPUTS(TEST_INPUTS_MMX_DWORD)
    push ARG1_64
    fld DWORD PTR [rsp]
    push ARG2_64
    fisub DWORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FISUBRm16, 2)
TEST_INPUTS(TEST_INPUTS_MMX_DWORD)
    push ARG1_64
    fld DWORD PTR [rsp]
    push ARG2_64
    fisubr WORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(FISUBRm32, 2)
TEST_INPUTS(TEST_INPUTS_MMX_DWORD)
    push ARG1_64
    fld DWORD PTR [rsp]
    push ARG2_64
    fisubr DWORD PTR [rsp]
TEST_END_64

