/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN_64(PMOVMSKBr32v64, 1)
TEST_INPUTS(
    0,
    0x8080808080808080,
    0xffffffffffffffff,
    0x80808080,
    0x8080808000000000,
    0x0080008000800080)

    movq mm0, ARG1_64
    pmovmskb eax, mm0
TEST_END_64

TEST_BEGIN_64(PMOVMSKBr32v128_0, 1)
TEST_INPUTS(
    0,
    0x8080808080808080,
    0xffffffffffffffff,
    0x80808080,
    0x8080808000000000,
    0x0080008000800080)

    movq xmm0, ARG1_64
    pmovmskb eax, xmm0
TEST_END_64

TEST_BEGIN_64(PMOVMSKBr32v128_4, 1)
TEST_INPUTS(
    0,
    0x8080808080808080,
    0xffffffffffffffff,
    0x80808080,
    0x8080808000000000,
    0x0080008000800080)

    movq xmm4, ARG1_64
    pmovmskb eax, xmm4
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VPMOVMSKBr32v256_0, 1)
TEST_INPUTS(
    0,
    0x8080808080808080,
    0xffffffffffffffff,
    0x80808080,
    0x8080808000000000,
    0x0080008000800080)

    vmovq xmm0, ARG1_64
    vpmovmskb eax, ymm0
TEST_END_64

TEST_BEGIN_64(VPMOVMSKBr32v256_4, 1)
TEST_INPUTS(
    0,
    0x8080808080808080,
    0xffffffffffffffff,
    0x80808080,
    0x8080808000000000,
    0x0080008000800080)

    vmovq xmm4, ARG1_64
    vpmovmskb eax, ymm4
TEST_END_64

#endif  // HAS_FEATURE_AVX
