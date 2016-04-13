/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(SUBPDv128v128_04, 1)
TEST_INPUTS(0)
    subpd xmm0, xmm4
TEST_END

TEST_BEGIN(SUBPDv128v128_40, 1)
TEST_INPUTS(0)
    subpd xmm4, xmm0
TEST_END

#if APPLE_SAFE_TESTS

TEST_BEGIN(SUBPDv128m128_04, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm4
    subpd xmm0, [rsp - 16]
TEST_END

TEST_BEGIN(SUBPDv128m128_40, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm0
    subpd xmm4, [rsp - 16]
TEST_END

#endif
