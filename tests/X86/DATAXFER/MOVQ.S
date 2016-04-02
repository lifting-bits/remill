/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

/* NOTE:
 * YMM0 - YMM3 are filled will 0xFF.
 * YMM4 and on are filled with 0x0. */

TEST_BEGIN_64(MOVQv128r64, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0xFFFF,
    0xFFFFFFFF,
    0xFFFFFFFFFFFFFFFF)

    movq xmm0, ARG1_64
TEST_END_64

TEST_BEGIN_64(MOVQv128r64_4, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0xFFFF,
    0xFFFFFFFF,
    0xFFFFFFFFFFFFFFFF)

    movq xmm4, ARG1_64
TEST_END_64

#if APPLE_SAFE_TESTS

TEST_BEGIN_64(MOVQv128m64, 1)
TEST_INPUTS(0)
    movq xmm0, [rsp - 16]
TEST_END_64

TEST_BEGIN_64(MOVQv128m64_4, 1)
TEST_INPUTS(0)
    movq xmm4, [rsp - 16]
TEST_END_64

#endif  // APPLE_SAFE_TESTS

TEST_BEGIN_64(MOVQr64v128, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0xFFFF,
    0xFFFFFFFF,
    0xFFFFFFFFFFFFFFFF)

    movq xmm0, ARG1_64
    movq ARG2_64, xmm0
    movq ARG1_64, xmm1
TEST_END_64

TEST_BEGIN_64(MOVQv128v128, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0xFFFF,
    0xFFFFFFFF,
    0xFFFFFFFFFFFFFFFF)

    movq xmm0, ARG1_64
    movq xmm1, xmm0
TEST_END_64

#if HAS_FEATURE_AVX
TEST_BEGIN_64(VMOVQv128r64, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0xFFFF,
    0xFFFFFFFF,
    0xFFFFFFFFFFFFFFFF)

    vmovq xmm0, ARG1_64
TEST_END_64

TEST_BEGIN_64(VMOVQv128v128, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0xFFFF,
    0xFFFFFFFF,
    0xFFFFFFFFFFFFFFFF)

    vmovq xmm0, ARG1_64
    vmovq xmm1, xmm0
TEST_END_64

TEST_BEGIN_64(VMOVQr64v128, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0xFFFF,
    0xFFFFFFFF,
    0xFFFFFFFFFFFFFFFF)

    vmovq xmm0, ARG1_64
    vmovq ARG2_64, xmm0
    vmovq ARG1_64, xmm1
TEST_END_64


#if APPLE_SAFE_TESTS

TEST_BEGIN_64(VMOVQv128m64, 1)
TEST_INPUTS(0)
    vmovq xmm0, [rsp - 16]
TEST_END_64

TEST_BEGIN_64(VMOVQv128m64_4, 1)
TEST_INPUTS(0)
    vmovq xmm4, [rsp - 16]
TEST_END_64

#endif  // APPLE_SAFE_TESTS
#endif
