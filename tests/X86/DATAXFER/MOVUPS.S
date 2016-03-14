/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(MOVUPSv128v128_1to0, 1)
TEST_INPUTS(
    0)
    movups xmm4, xmm0
TEST_END


TEST_BEGIN(MOVUPSv128v128_0to1, 1)
TEST_INPUTS(
    0)
    movups xmm0, xmm4
TEST_END

#if HAS_FEATURE_AVX

TEST_BEGIN(VMOVUPSv128v128_1to0, 1)
TEST_INPUTS(
    0)
    vmovups xmm4, xmm0
TEST_END

TEST_BEGIN(VMOVUPSv128v128_0to1, 1)
TEST_INPUTS(
    0)
    vmovups xmm0, xmm4
TEST_END

TEST_BEGIN(VMOVUPSv256v256_1to0, 1)
TEST_INPUTS(
    0)
    vmovups ymm4, ymm0
TEST_END

TEST_BEGIN(VMOVUPSv256v256_0to1, 1)
TEST_INPUTS(
    0)
    vmovups ymm0, ymm4
TEST_END

#endif
