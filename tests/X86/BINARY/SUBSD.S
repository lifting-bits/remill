/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(SUBSDv128v128_04, 1)
TEST_INPUTS(0)
    subsd xmm0, xmm4
TEST_END

TEST_BEGIN(SUBSDv128v128_40, 1)
TEST_INPUTS(0)
    subsd xmm4, xmm0
TEST_END

#if APPLE_SAFE_TESTS

TEST_BEGIN(SUBSDv128m128_04, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm4
    subsd xmm0, [rsp - 16]
TEST_END

TEST_BEGIN(SUBSDv128m128_40, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm0
    subsd xmm4, [rsp - 16]
TEST_END

#endif

#if HAS_FEATUR_AVX
TEST_BEGIN(VSUBSDv128v128_04, 1)
TEST_INPUTS(0)
    vsubsd xmm0, xmm1, xmm4
TEST_END

TEST_BEGIN(VSUBSDv128v128_40, 1)
TEST_INPUTS(0)
    vsubsd xmm1, xmm4, xmm0
TEST_END

TEST_BEGIN(VSUBSDv256v256_04, 1)
TEST_INPUTS(0)
    vsubsd ymm0, ymm1, ymm4
TEST_END

TEST_BEGIN(VSUBSDv256v256_40, 1)
TEST_INPUTS(0)
    vsubsd ymm1, ymm4, ymm0
TEST_END
#endif
