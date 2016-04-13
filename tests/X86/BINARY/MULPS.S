/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(MULPSv128v128_01, 1)
TEST_INPUTS(0)
    mulps xmm0, xmm1
TEST_END

TEST_BEGIN(MULPSv128v128_45, 1)
TEST_INPUTS(0)
    mulps xmm4, xmm5
TEST_END

#if APPLE_SAFE_TESTS

TEST_BEGIN(MULPSv128m128_01, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm1
    mulps xmm0, [rsp - 16]
TEST_END

TEST_BEGIN(MULPSv128m128_45, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm5
    mulps xmm4, [rsp - 16]
TEST_END

#endif

#if HAS_FEATUR_AVX
TEST_BEGIN(VMULPSv128v128_01, 1)
TEST_INPUTS(0)
    vmulps xmm0, xmm0, xmm1
TEST_END

TEST_BEGIN(VMULPSv128v128_45, 1)
TEST_INPUTS(0)
    vmulps xmm1, xmm4, xmm5
TEST_END

TEST_BEGIN(VMULPSv256v256_01, 1)
TEST_INPUTS(0)
    vmulps ymm0, ymm0, ymm1
TEST_END

TEST_BEGIN(VMULPSv256v256_45, 1)
TEST_INPUTS(0)
    vmulps ymm1, ymm4, ymm5
TEST_END
#endif
