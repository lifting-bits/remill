/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(MULPDv128v128_01, 1)
TEST_INPUTS(0)
    mulpd xmm0, xmm1
TEST_END

TEST_BEGIN(MULPDv128v128_45, 1)
TEST_INPUTS(0)
    mulpd xmm4, xmm5
TEST_END

#if APPLE_SAFE_TESTS

TEST_BEGIN(MULPDv128m128_01, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm1
    mulpd xmm0, [rsp - 16]
TEST_END

TEST_BEGIN(MULPDv128m128_45, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm5
    mulpd xmm4, [rsp - 16]
TEST_END

#endif

#if HAS_FEATUR_AVX
TEST_BEGIN(VMULPDv128v128_01, 1)
TEST_INPUTS(0)
    vmulpd xmm0, xmm0, xmm1
TEST_END

TEST_BEGIN(VMULPDv128v128_45, 1)
TEST_INPUTS(0)
    vmulpd xmm1, xmm4, xmm5
TEST_END

TEST_BEGIN(VMULPDv256v256_01, 1)
TEST_INPUTS(0)
    vmulpd ymm0, ymm0, ymm1
TEST_END

TEST_BEGIN(VMULPDv256v256_45, 1)
TEST_INPUTS(0)
    vmulpd ymm1, ymm4, ymm5
TEST_END
#endif
