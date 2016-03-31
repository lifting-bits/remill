/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#if APPLE_SAFE_TESTS

TEST_BEGIN(MOVLPSv128m64, 1)
TEST_INPUTS(
    0)
#ifdef IN_TEST_GENERATOR
    .byte IF_64_BIT(0x48, ) 0x8D, 0x74, 0x24, 0xF8
#else
    lea ARG2_ADDR, [SP_ADDR - 8]
#endif
    movlps xmm0,QWORD PTR [ARG2_64]
TEST_END

TEST_BEGIN(MOVLPSm64v128, 1)
TEST_INPUTS(
    0)
#ifdef IN_TEST_GENERATOR
    .byte IF_64_BIT(0x48, ) 0x8D, 0x74, 0x24, 0xF8
#else
    lea ARG2_ADDR, [SP_ADDR - 8]
#endif
    movlps QWORD PTR [ARG2_64], xmm0
TEST_END

#if HAS_FEATURE_AVX

TEST_BEGIN(VMOVLPSv128m64, 1)
TEST_INPUTS(
    0)
#ifdef IN_TEST_GENERATOR
    .byte IF_64_BIT(0x48, ) 0x8D, 0x74, 0x24, 0xF8
#else
    lea ARG2_ADDR, [SP_ADDR - 8]
#endif
    vmovlps xmm0, xmm1, QWORD PTR [ARG2_64]
TEST_END

TEST_BEGIN(VMOVLPSm64v128, 1)
TEST_INPUTS(
    0)
#ifdef IN_TEST_GENERATOR
    .byte IF_64_BIT(0x48, ) 0x8D, 0x74, 0x24, 0xF8
#else
    lea ARG2_ADDR, [SP_ADDR - 8]
#endif
    vmovlps QWORD PTR [ARG2_64], xmm0
TEST_END


#endif

#endif  // __APPLE__
