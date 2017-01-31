/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN_64(CVTSS2SDv128m32, 1)
TEST_INPUTS(
    0x3fffffff,
    0x40000000,
    0x7FFFFFFF,
    0x80000000)

    push ARG1_64
    cvtss2sd xmm0, DWORD PTR [rsp]
TEST_END_64

TEST_BEGIN(CVTSS2SDv128v128, 1)
TEST_INPUTS(0)
    cvtss2sd xmm0, xmm1
    cvtss2sd xmm1, xmm2
    cvtss2sd xmm2, xmm3
    cvtss2sd xmm3, xmm4
TEST_END

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VCVTSS2SDv128v128m64, 1)
TEST_INPUTS(
    0x3fffffff,
    0x40000000,
    0x7FFFFFFF,
    0x80000000)

    push ARG1_64
    vcvtss2sd xmm0, xmm1, DWORD PTR [rsp]
TEST_END_64

TEST_BEGIN(VCVTSS2SDv128v128v128, 1)
TEST_INPUTS(0)
    vcvtss2sd xmm0, xmm1, xmm2
    vcvtss2sd xmm1, xmm2, xmm3
    vcvtss2sd xmm2, xmm3, xmm4
    vcvtss2sd xmm3, xmm4, xmm5
TEST_END

#endif  // HAS_FEATURE_AVX
