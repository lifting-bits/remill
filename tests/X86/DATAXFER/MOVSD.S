/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#if APPLE_SAFE_TESTS

TEST_BEGIN(MOVSDv128m64, 1)
TEST_INPUTS(
    0)
    movsd xmm0,QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(MOVSDm64v128, 1)
TEST_INPUTS(
    0)
    movsd QWORD PTR [rsp - 8], xmm0
TEST_END

#endif  // APPLE_SAFE_TESTS

TEST_BEGIN(MOVSDv12v128, 1)
TEST_INPUTS(
    0)
    movsd xmm0, xmm4
TEST_END

TEST_BEGIN(MOVSDv12v128_4, 1)
TEST_INPUTS(
    0)
    movsd xmm4, xmm0
TEST_END
