/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(MOVDv128r32, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0xFFFF,
    0xFFFFFFFF)

    movd xmm0, ARG1_32
TEST_END

TEST_BEGIN(MOVDr32v128, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0xFFFF,
    0xFFFFFFFF)

    movd xmm0, ARG1_32
    movd ARG2_32, xmm0
TEST_END

#if HAS_FEATURE_AVX
TEST_BEGIN(VMOVDv128r32, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0xFFFF,
    0xFFFFFFFF)

    vmovd xmm0, ARG1_32
TEST_END

TEST_BEGIN(VMOVDr32v128, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0xFFFF,
    0xFFFFFFFF)

    vmovd xmm0, ARG1_32
    vmovd ARG2_32, xmm0
TEST_END
#endif
