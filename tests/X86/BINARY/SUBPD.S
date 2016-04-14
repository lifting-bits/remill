/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(SUBPDv128v128_04, 1)
TEST_INPUTS(0)
    subpd xmm0, xmm4
TEST_END

TEST_BEGIN(SUBPDv128v128_40, 1)
TEST_INPUTS(0)
    subpd xmm4, xmm0
TEST_END

#if APPLE_SAFE_TESTS

TEST_BEGIN(SUBPDv128m128_04, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm4
    subpd xmm0, [rsp - 16]
TEST_END

TEST_BEGIN(SUBPDv128m128_40, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm0
    subpd xmm4, [rsp - 16]
TEST_END

#endif  // APPLE_SAFE_TESTS

#if HAS_FEATURE_AVX
TEST_BEGIN(VSUBPDv128v128_04, 1)
TEST_INPUTS(0)
    vsubpd xmm0, xmm1, xmm4
TEST_END

TEST_BEGIN(VSUBPDv128v128_40, 1)
TEST_INPUTS(0)
    vsubpd xmm1, xmm4, xmm0
TEST_END

TEST_BEGIN(VSUBPDv256v256_04, 1)
TEST_INPUTS(0)
    vsubpd ymm0, ymm1, ymm4
TEST_END

TEST_BEGIN(VSUBPDv256v256_40, 1)
TEST_INPUTS(0)
    vsubpd ymm1, ymm4, ymm0
TEST_END

#if APPLE_SAFE_TESTS
TEST_BEGIN(VSUBPDv128m128_45, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm5
    vsubpd xmm1, xmm4, [rsp - 16]
TEST_END

TEST_BEGIN(VSUBPDv256m256_45, 1)
TEST_INPUTS(0)
    vmovdqu [rsp - 32], ymm5
    vsubpd ymm1, ymm4, [rsp - 32]
TEST_END
#endif  // APPLE_SAFE_TESTS
#endif  // HAS_FEATURE_AVX
