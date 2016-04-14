/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(DIVPDv128v128_40, 1)
TEST_INPUTS(0)
    divpd xmm4, xmm0
TEST_END

TEST_BEGIN(DIVPDv128v128_45, 1)
TEST_INPUTS(0)
    divpd xmm4, xmm5
TEST_END

#if APPLE_SAFE_TESTS

TEST_BEGIN(DIVPDv128m128_40, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm0
    divpd xmm4, [rsp - 16]
TEST_END

TEST_BEGIN(DIVPDv128m128_45, 1)
TEST_INPUTS(0)
    divpd xmm4, [rsp - 16]
TEST_END

#endif

#if HAS_FEATURE_AVX
TEST_BEGIN(VDIVPDv128v128_40, 1)
TEST_INPUTS(0)
    vdivpd xmm0, xmm4, xmm0
TEST_END

TEST_BEGIN(VDIVPDv128v128_45, 1)
TEST_INPUTS(0)
    vdivpd xmm1, xmm4, xmm5
TEST_END

TEST_BEGIN(VDIVPDv256v256_40, 1)
TEST_INPUTS(0)
    vdivpd ymm0, ymm4, ymm0
TEST_END

TEST_BEGIN(VDIVPDv256v256_45, 1)
TEST_INPUTS(0)
    vdivpd ymm1, ymm4, ymm5
TEST_END

#if APPLE_SAFE_TESTS
TEST_BEGIN(VDIVPDv128m128_45, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm5
    vdivpd xmm1, xmm4, [rsp - 16]
TEST_END

TEST_BEGIN(VDIVPDv256m256_45, 1)
TEST_INPUTS(0)
    vmovdqu [rsp - 32], ymm5
    vdivpd ymm1, ymm4, [rsp - 32]
TEST_END
#endif  // APPLE_SAFE_TESTS
#endif
