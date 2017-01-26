/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(FXCHst0st0, 1)
TEST_INPUTS(0)
    fldl2e
    fldlg2
    fxch st(0)
TEST_END

TEST_BEGIN(FXCHst0st1, 1)
TEST_INPUTS(0)
    fldl2e
    fldlg2
    fxch
TEST_END

TEST_BEGIN(FXCHst0st2, 1)
TEST_INPUTS(0)
    fldl2e
    fldlg2
    fldpi
    fxch st(2)
TEST_END
