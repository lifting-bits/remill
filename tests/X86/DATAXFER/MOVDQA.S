/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

/* NOTE:
 * YMM0 - YMM3 are filled will 0xFF.
 * YMM4 and on are filled with 0x0. */

TEST_BEGIN(MOVDQAv128v128_1to0, 1)
TEST_INPUTS(
    0)
    movdqa xmm4, xmm0
TEST_END

TEST_BEGIN(MOVDQAv128v128_0to1, 1)
TEST_INPUTS(
    0)
    movdqa xmm0, xmm4
TEST_END

#if APPLE_SAFE_TESTS
TEST_BEGIN(MOVDQAv128m128, 1)
TEST_INPUTS(
    0)
    movdqa xmm0, [rsp - 128]
TEST_END

TEST_BEGIN(MOVDQAv128m128_4, 1)
TEST_INPUTS(
    0)
    movdqa xmm4, [rsp - 128]
TEST_END
#endif  // APPLE_SAFE_TESTS

#if HAS_FEATURE_AVX

TEST_BEGIN(VMOVDQAv128v128_1to0, 1)
TEST_INPUTS(
    0)
    vmovdqa xmm4, xmm0
TEST_END

TEST_BEGIN(VMOVDQAv128v128_0to1, 1)
TEST_INPUTS(
    0)
    vmovdqa xmm0, xmm4
TEST_END

TEST_BEGIN(VMOVDQAv256v256_1to0, 1)
TEST_INPUTS(
    0)
    vmovdqa ymm4, ymm0
TEST_END

TEST_BEGIN(VMOVDQAv256v256_0to1, 1)
TEST_INPUTS(
    0)
    vmovdqa ymm0, ymm4
TEST_END

#if APPLE_SAFE_TESTS
TEST_BEGIN(VMOVDQAv128m128, 1)
TEST_INPUTS(
    0)
    vmovdqa xmm0, [rsp - 128]
TEST_END

TEST_BEGIN(VMOVDQAv128m128_4, 1)
TEST_INPUTS(
    0)
    vmovdqa xmm4, [rsp - 128]
TEST_END
#endif  // APPLE_SAFE_TESTS
#endif  // HAS_FEATURE_AVX
