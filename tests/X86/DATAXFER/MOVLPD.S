/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#if APPLE_SAFE_TESTS

TEST_BEGIN(MOVLPDv128m64, 1)
TEST_INPUTS(
    0)
    movlpd xmm0,QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(MOVLPDv128m64_4, 1)
TEST_INPUTS(
    0)
    movlpd xmm4,QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(MOVLPDm64v128, 1)
TEST_INPUTS(
    0)
    movlpd QWORD PTR [rsp - 8], xmm0
TEST_END

TEST_BEGIN(MOVLPDm64v128_4, 1)
TEST_INPUTS(
    0)
    movlpd QWORD PTR [rsp - 8], xmm4
TEST_END

#if HAS_FEATURE_AVX

TEST_BEGIN(VMOVLPDv128m64, 1)
TEST_INPUTS(
    0)
    vmovlpd xmm0, xmm1, QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(VMOVLPDv128m64_4, 1)
TEST_INPUTS(
    0)
    vmovlpd xmm4, xmm1, QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(VMOVLPDm64v128, 1)
TEST_INPUTS(
    0)
    vmovlpd QWORD PTR [rsp - 8], xmm0
TEST_END

TEST_BEGIN(VMOVLPDm64v128_4, 1)
TEST_INPUTS(
    0)
    vmovlpd QWORD PTR [rsp - 8], xmm4
TEST_END

#endif  // HAS_FEATURE_AVX
#endif  // APPLE_SAFE_TESTS
