/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN_64(FCOMst0st1, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    fcom
TEST_END_64

TEST_BEGIN_64(FCOMst0st2, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    fcom st(2)
TEST_END_64

TEST_BEGIN_64(FCOMPst0st1, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    fcomp
TEST_END_64

TEST_BEGIN_64(FCOMPst0st2, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    fcomp st(2)
TEST_END_64

TEST_BEGIN_64(FCOMPPst0st1, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    fldpi
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    fcompp
TEST_END_64

TEST_BEGIN_64(FCOMIst0st2, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    fcomi st(2)
TEST_END_64

TEST_BEGIN_64(FCOMIPst0st2, 2)
TEST_INPUTS(TEST_INPUTS_MMX_QWORD)
    push ARG1_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    push ARG2_64
    fld QWORD PTR [rsp]
    fcomip st(2)
TEST_END_64
