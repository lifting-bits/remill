/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(MULSSv128v128_01, 1)
TEST_INPUTS(0)
    mulss xmm0, xmm1
TEST_END

TEST_BEGIN(MULSSv128v128_45, 1)
TEST_INPUTS(0)
    mulss xmm4, xmm5
TEST_END

#if APPLE_SAFE_TESTS

TEST_BEGIN(MULSSv128m128_01, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm1
    mulss xmm0, [rsp - 16]
TEST_END

TEST_BEGIN(MULSSv128m128_45, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm5
    mulss xmm4, [rsp - 16]
TEST_END

#endif

#if HAS_FEATUR_AVX
TEST_BEGIN(VMULSSv128v128_01, 1)
TEST_INPUTS(0)
    vmulss xmm0, xmm0, xmm1
TEST_END

TEST_BEGIN(VMULSSv128v128_45, 1)
TEST_INPUTS(0)
    vmulss xmm1, xmm4, xmm5
TEST_END

TEST_BEGIN(VMULSSv256v256_01, 1)
TEST_INPUTS(0)
    vmulss ymm0, ymm0, ymm1
TEST_END

TEST_BEGIN(VMULSSv256v256_45, 1)
TEST_INPUTS(0)
    vmulss ymm1, ymm4, ymm5
TEST_END
#endif
