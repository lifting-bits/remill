/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(ADDPDv128v128_04, 1)
TEST_INPUTS(0)
    addpd xmm0, xmm4
TEST_END

TEST_BEGIN(ADDPDv128v128_40, 1)
TEST_INPUTS(0)
    addpd xmm4, xmm0
TEST_END

#if APPLE_SAFE_TESTS

TEST_BEGIN(ADDPDv128m128_04, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm4
    addpd xmm0, [rsp - 16]
TEST_END

TEST_BEGIN(ADDPDv128m128_40, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm0
    addpd xmm4, [rsp - 16]
TEST_END

#endif  // APPLE_SAFE_TESTS

#if HAS_FEATURE_AVX
TEST_BEGIN(VADDPDv128v128_04, 1)
TEST_INPUTS(0)
    vaddpd xmm0, xmm1, xmm4
TEST_END

TEST_BEGIN(VADDPDv128v128_40, 1)
TEST_INPUTS(0)
    vaddpd xmm1, xmm4, xmm0
TEST_END

TEST_BEGIN(VADDPDv256v256_04, 1)
TEST_INPUTS(0)
    vaddpd ymm0, ymm1, ymm4
TEST_END

TEST_BEGIN(VADDPDv256v256_40, 1)
TEST_INPUTS(0)
    vaddpd ymm1, ymm4, ymm0
TEST_END

#if APPLE_SAFE_TESTS
TEST_BEGIN(VADDPDv128m128_45, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm5
    vaddpd xmm1, xmm4, [rsp - 16]
TEST_END

TEST_BEGIN(VADDPDv256m256_45, 1)
TEST_INPUTS(0)
    vmovdqu [rsp - 32], ymm5
    vaddpd ymm1, ymm4, [rsp - 32]
TEST_END
#endif  // APPLE_SAFE_TESTS
#endif  // HAS_FEATURE_AVX
