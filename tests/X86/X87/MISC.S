/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN_64(FNOP, 1)
TEST_INPUTS(0)
    fnop
TEST_END_64

TEST_BEGIN_64(FWAIT, 1)
TEST_INPUTS(0)
    fwait
TEST_END_64

TEST_BEGIN_64(FABS, 1)
TEST_INPUTS(
    0x7ff0000000000000,  /* +inf */
    0xfff0000000000000,  /* -inf */
    0x3fe0000000000000,  /* 0.5 */
    0xbfe0000000000000  /* -0.5 */)

    push ARG1_64
    fld QWORD PTR [rsp]
    fabs
TEST_END_64

TEST_BEGIN_64(FCHS, 1)
TEST_INPUTS(
    0x7ff0000000000000,  /* +inf */
    0xfff0000000000000,  /* -inf */
    0x3fe0000000000000,  /* 0.5 */
    0xbfe0000000000000  /* -0.5 */)

    push ARG1_64
    fld QWORD PTR [rsp]
    fchs
TEST_END_64

TEST_BEGIN_64(FCOS, 1)
TEST_INPUTS(
    0x4058ff5c28f5c28f,  /* 99.99 */
    0xc058ff5c28f5c28f  /* -99.99 */)

    push ARG1_64
    fld QWORD PTR [rsp]
    fcos
TEST_END_64

TEST_BEGIN_64(FSIN, 1)
TEST_INPUTS(
    0x4058ff5c28f5c28f,  /* 99.99 */
    0xc058ff5c28f5c28f  /* -99.99 */)

    push ARG1_64
    fld QWORD PTR [rsp]
    fsin
TEST_END_64

TEST_BEGIN(FPTAN, 1)
TEST_INPUTS(0)
    fldl2e
    fptan
TEST_END

TEST_BEGIN(FPATAN, 1)
TEST_INPUTS(0)
    fldl2e
    fldlg2
    fpatan
TEST_END
