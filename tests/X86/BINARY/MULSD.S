/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(MULSDv128v128_01, 1)
TEST_INPUTS(0)
    mulsd xmm0, xmm1
TEST_END

TEST_BEGIN(MULSDv128v128_45, 1)
TEST_INPUTS(0)
    mulsd xmm4, xmm5
TEST_END

#if APPLE_SAFE_TESTS

TEST_BEGIN(MULSDv128m128_01, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm1
    mulsd xmm0, [rsp - 16]
TEST_END

TEST_BEGIN(MULSDv128m128_45, 1)
TEST_INPUTS(0)
    movdqu [rsp - 16], xmm5
    mulsd xmm4, [rsp - 16]
TEST_END

#endif

#if HAS_FEATURE_AVX
TEST_BEGIN(VMULSDv128v128_01, 1)
TEST_INPUTS(0)
    vmulsd xmm0, xmm0, xmm1
TEST_END

TEST_BEGIN(VMULSDv128v128_45, 1)
TEST_INPUTS(0)
    vmulsd xmm1, xmm4, xmm5
TEST_END

#if APPLE_SAFE_TESTS
TEST_BEGIN_64(VMULSDv128m64_45, 3)
TEST_INPUTS(
    0x3ff0000000000000,
    0x400921fb54442d18,
    0x40f869f000000000)

    mov QWORD PTR [rsp - 16], ARG1_64
    vmulsd xmm1, xmm4, QWORD PTR [rsp - 16]
TEST_END_64
#endif  // APPLE_SAFE_TESTS

#endif
