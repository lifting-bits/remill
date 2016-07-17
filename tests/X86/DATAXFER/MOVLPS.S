/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#if APPLE_SAFE_TESTS

TEST_BEGIN(MOVLPSv128m64, 1)
TEST_INPUTS(
    0)
    movlps xmm0,QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(MOVLPSv128m64_4, 1)
TEST_INPUTS(
    0)
    movlps xmm4, QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(MOVLPSm64v128, 1)
TEST_INPUTS(
    0)
    movlps QWORD PTR [rsp - 8], xmm0
TEST_END

TEST_BEGIN(MOVLPSm64v128_4, 1)
TEST_INPUTS(
    0)
    movlps QWORD PTR [rsp - 8], xmm4
TEST_END

#if HAS_FEATURE_AVX

TEST_BEGIN(VMOVLPSvv128v128m64_0_1, 1)
TEST_INPUTS(
    0,
    0x3de353f8,
    0x411ffbe73de353f8)
    vmovlps xmm0, xmm1, QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(VMOVLPSvv128v128m64_4_1, 1)
TEST_INPUTS(
    0,
    0x3de353f8,
    0x411ffbe73de353f8)
    vmovlps xmm4, xmm1, QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(VMOVLPSvv128v128m64_1_4, 1)
TEST_INPUTS(
    0,
    0x3de353f8,
    0x411ffbe73de353f8)
    vmovlps xmm1, xmm4, QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(VMOVLPSm64v128, 1)
TEST_INPUTS(
    0)
    vmovlps QWORD PTR [rsp - 8], xmm0
TEST_END

TEST_BEGIN(VMOVLPSm64v128_4, 1)
TEST_INPUTS(
    0)
    vmovlps QWORD PTR [rsp - 8], xmm4
TEST_END

#endif  // HAS_FEATURE_AVX
#endif  // APPLE_SAFE_TESTS
