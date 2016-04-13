/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(SUBPSv128v128_04, 1)
TEST_INPUTS(0)
    subps xmm0, xmm4
TEST_END

TEST_BEGIN(SUBPSv128v128_40, 1)
TEST_INPUTS(0)
    subps xmm4, xmm0
TEST_END

#if APPLE_SAFE_TESTS

TEST_BEGIN(SUBPSv128m128_04, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm4
    subps xmm0, [rsp - 16]
TEST_END

TEST_BEGIN(SUBPSv128m128_40, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm0
    subps xmm4, [rsp - 16]
TEST_END

#endif

#if HAS_FEATUR_AVX
TEST_BEGIN(VSUBPSv128v128_04, 1)
TEST_INPUTS(0)
    vsubps xmm0, xmm1, xmm4
TEST_END

TEST_BEGIN(VSUBPSv128v128_40, 1)
TEST_INPUTS(0)
    vsubps xmm1, xmm4, xmm0
TEST_END

TEST_BEGIN(VSUBPSv256v256_04, 1)
TEST_INPUTS(0)
    vsubps ymm0, ymm1, ymm4
TEST_END

TEST_BEGIN(VSUBPSv256v256_40, 1)
TEST_INPUTS(0)
    vsubps ymm1, ymm4, ymm0
TEST_END
#endif
