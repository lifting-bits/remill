/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(CVTSI2SDv128r32, 1)
TEST_INPUTS(
    0,
    1,
    0xffffffff,
    0x7fffffff,
    0x80000000)

    cvtsi2ss xmm0, ARG1_32
TEST_END

TEST_BEGIN_64(CVTSI2SDv128r64, 1)
TEST_INPUTS(
    0,
    1,
    0xffffffff,
    0x7fffffff,
    0x80000000,
    0xffffffffffffffff,
    0x7fffffffffffffff,
    0x8000000000000000)

    cvtsi2ss xmm0, ARG1_64
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN(VCVTSI2SDv128v128r32, 1)
TEST_INPUTS(
    0,
    1,
    0xffffffff,
    0x7fffffff,
    0x80000000)

    vcvtsi2ss xmm0, xmm1, ARG1_32
TEST_END

TEST_BEGIN_64(VCVTSI2SDv128v128r64, 1)
TEST_INPUTS(
    0,
    1,
    0xffffffff,
    0x7fffffff,
    0x80000000,
    0xffffffffffffffff,
    0x7fffffffffffffff,
    0x8000000000000000)

    vcvtsi2ss xmm0, xmm1, ARG1_64
TEST_END_64

#endif  // HAS_FEATURE_AVX
