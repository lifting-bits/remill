/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(ADDPSv128v128_04, 1)
TEST_INPUTS(0)
    addps xmm0, xmm4
TEST_END

TEST_BEGIN(ADDPSv128v128_40, 1)
TEST_INPUTS(0)
    addps xmm4, xmm0
TEST_END

#if APPLE_SAFE_TESTS

TEST_BEGIN(ADDPSv128m128_04, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm4
    addps xmm0, [rsp - 16]
TEST_END

TEST_BEGIN(ADDPSv128m128_40, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm0
    addps xmm4, [rsp - 16]
TEST_END

#endif  // APPLE_SAFE_TESTS

#if HAS_FEATURE_AVX
TEST_BEGIN(VADDPSv128v128_04, 1)
TEST_INPUTS(0)
    vaddps xmm0, xmm1, xmm4
TEST_END

TEST_BEGIN(VADDPSv128v128_40, 1)
TEST_INPUTS(0)
    vaddps xmm1, xmm4, xmm0
TEST_END

TEST_BEGIN(VADDPSv256v256_04, 1)
TEST_INPUTS(0)
    vaddps ymm0, ymm1, ymm4
TEST_END

TEST_BEGIN(VADDPSv256v256_40, 1)
TEST_INPUTS(0)
    vaddps ymm1, ymm4, ymm0
TEST_END

#if APPLE_SAFE_TESTS
TEST_BEGIN(VADDPSv128m128_40, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm0
    vaddps xmm1, xmm4, [rsp - 16]
TEST_END

TEST_BEGIN(VADDPSv256m256_40, 1)
TEST_INPUTS(0)
    vmovdqu [rsp - 32], ymm0
    vaddps ymm1, ymm4, [rsp - 32]
TEST_END
#endif  // APPLE_SAFE_TESTS
#endif  // HAS_FEATURE_AVX
