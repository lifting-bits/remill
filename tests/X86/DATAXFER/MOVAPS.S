/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(MOVAPSv128v128_1to0, 1)
TEST_INPUTS(
    0)
    movaps xmm4, xmm0
TEST_END


TEST_BEGIN(MOVAPSv128v128_0to1, 1)
TEST_INPUTS(
    0)
    movaps xmm0, xmm4
TEST_END

#if HAS_FEATURE_AVX

TEST_BEGIN(VMOVAPSv128v128_1to0, 1)
TEST_INPUTS(
    0)
    vmovaps xmm4, xmm0
TEST_END

TEST_BEGIN(VMOVAPSv128v128_0to1, 1)
TEST_INPUTS(
    0)
    vmovaps xmm0, xmm4
TEST_END

TEST_BEGIN(VMOVAPSv256v256_1to0, 1)
TEST_INPUTS(
    0)
    vmovaps ymm4, ymm0
TEST_END

TEST_BEGIN(VMOVAPSv256v256_0to1, 1)
TEST_INPUTS(
    0)
    vmovaps ymm0, ymm4
TEST_END

#endif
