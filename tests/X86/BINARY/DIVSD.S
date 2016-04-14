/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(DIVSDv128v128_40, 1)
TEST_INPUTS(0)
    divsd xmm4, xmm0
TEST_END

TEST_BEGIN(DIVSDv128v128_45, 1)
TEST_INPUTS(0)
    divsd xmm4, xmm5
TEST_END

#if APPLE_SAFE_TESTS

TEST_BEGIN(DIVSDv128m128_40, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm0
    divsd xmm4, [rsp - 16]
TEST_END

TEST_BEGIN(DIVSDv128m128_45, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm5
    divsd xmm4, [rsp - 16]
TEST_END

#endif  // APPLE_SAFE_TESTS

#if HAS_FEATURE_AVX
TEST_BEGIN(VDIVSDv128v128_40, 1)
TEST_INPUTS(0)
    vdivsd xmm0, xmm4, xmm0
TEST_END

TEST_BEGIN(VDIVSDv128v128_45, 1)
TEST_INPUTS(0)
    vdivsd xmm1, xmm4, xmm5
TEST_END

#if APPLE_SAFE_TESTS
TEST_BEGIN_64(VDIVSDv128m64_45, 3)
TEST_INPUTS(
    0x3ff0000000000000,
    0x400921fb54442d18,
    0x40f869f000000000)

    mov QWORD PTR [rsp - 16], ARG1_64
    vdivsd xmm1, xmm4, QWORD PTR [rsp - 16]
TEST_END_64
#endif  // APPLE_SAFE_TESTS
#endif  // HAS_FEATURE_AVX
