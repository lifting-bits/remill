/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#if APPLE_SAFE_TESTS

TEST_BEGIN(MOVSDv128m64, 1)
TEST_INPUTS(
    0)
    movsd xmm0,QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(MOVSDv128m64_4, 1)
TEST_INPUTS(
    0)
    movsd xmm1,QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(MOVSDm64v128, 1)
TEST_INPUTS(
    0)
    movsd QWORD PTR [rsp - 8], xmm0
TEST_END

#endif  // APPLE_SAFE_TESTS

TEST_BEGIN(MOVSDv128v128, 1)
TEST_INPUTS(
    0)
    movsd xmm0, xmm4
TEST_END

TEST_BEGIN(MOVSDv128v128_4, 1)
TEST_INPUTS(
    0)
    movsd xmm4, xmm0
TEST_END

#if HAS_FEATURE_AVX
#if APPLE_SAFE_TESTS

TEST_BEGIN(VMOVSDv128m64, 1)
TEST_INPUTS(
    0)
    vmovsd xmm0, QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(VMOVSDv128m64_4, 1)
TEST_INPUTS(
    0)
    vmovsd xmm4, QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(VMOVSDm64v128, 1)
TEST_INPUTS(
    0)
    vmovsd QWORD PTR [rsp - 8], xmm0
TEST_END

TEST_BEGIN(VMOVSDm64v128_4, 1)
TEST_INPUTS(
    0)
    vmovsd QWORD PTR [rsp - 8], xmm4
TEST_END

TEST_BEGIN(VMOVSDv128v128v128, 1)
TEST_INPUTS(
    0)
    vmovsd xmm0, xmm1, xmm4
TEST_END

TEST_BEGIN(VMOVSDv128v128v128_4, 1)
TEST_INPUTS(
    0)
    vmovsd xmm4, xmm1, xmm0
TEST_END
#endif  // APPLE_SAFE_TESTS
#endif  // HAS_FEATURE_AVX
