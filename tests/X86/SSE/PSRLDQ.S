/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(PSRLDQv128v128i8, 1)
TEST_INPUTS(
    0)
    psrldq xmm0, 0
    psrldq xmm1, 1
    psrldq xmm2, 2
    psrldq xmm3, 3
    psrldq xmm4, 4
    psrldq xmm5, 14
    psrldq xmm6, 15
    psrldq xmm7, 16
TEST_END

#if HAS_FEATURE_AVX

TEST_BEGIN(VPSRLDQv128v128i8, 1)
TEST_INPUTS(
    0)
    vpsrldq xmm1, xmm0, 1
    vpsrldq xmm2, xmm0, 2
    vpsrldq xmm3, xmm0, 3
    vpsrldq xmm4, xmm0, 4
    vpsrldq xmm5, xmm0, 14
    vpsrldq xmm6, xmm0, 15
    vpsrldq xmm7, xmm0, 16
TEST_END

TEST_BEGIN(VPSRLDQv256v256i8, 1)
TEST_INPUTS(
    0)
    vpsrldq ymm1, ymm0, 1
    vpsrldq ymm2, ymm0, 2
    vpsrldq ymm3, ymm0, 3
    vpsrldq ymm4, ymm0, 4
    vpsrldq ymm5, ymm0, 14
    vpsrldq ymm6, ymm0, 15
    vpsrldq ymm7, ymm0, 16
TEST_END

#endif  // HAS_FEATURE_AVX
