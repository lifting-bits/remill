/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#if APPLE_SAFE_TESTS

TEST_BEGIN(CVTSS2SIr32m32, 1)
TEST_INPUTS(
    0x7f7fffff,  // std::numeric_limits<float>::max()
    0x00800000,  // std::numeric_limits<float>::min()
    0x3f800000,  // +1.0
    0xbf800000,  // -1.0
    0x00000000,  // +0.0
    0x80000000,  // -0.0
    0x3f000000,  // +0.5
    0xbf000000,  // -0.5
    0x47c34fc0)  // 99999.5

    mov [rsp - 4], ARG1_32
    cvtss2si eax, [rsp - 4]
TEST_END

#endif  // APPLE_SAFE_TESTS

TEST_BEGIN(CVTSS2SIr32v128, 1)
TEST_INPUTS(
    0x7f7fffff,  // std::numeric_limits<float>::max()
    0x00800000,  // std::numeric_limits<float>::min()
    0x3f800000,  // +1.0
    0xbf800000,  // -1.0
    0x00000000,  // +0.0
    0x80000000,  // -0.0
    0x3f000000,  // +0.5
    0xbf000000,  // -0.5
    0x47c34fc0)  // 99999.5

    movd xmm0, ARG1_32
    cvtss2si eax, xmm0
TEST_END

#if APPLE_SAFE_TESTS

TEST_BEGIN_64(CVTSS2SIr64m32, 1)
TEST_INPUTS(
    0x7f7fffff,  // std::numeric_limits<float>::max()
    0x00800000,  // std::numeric_limits<float>::min()
    0x3f800000,  // +1.0
    0xbf800000,  // -1.0
    0x00000000,  // +0.0
    0x80000000,  // -0.0
    0x3f000000,  // +0.5
    0xbf000000,  // -0.5
    0x47c34fc0)  // 99999.5

    mov [rsp - 4], ARG1_32
    cvtss2si rax, [rsp - 4]
TEST_END_64

#endif  // APPLE_SAFE_TESTS

TEST_BEGIN_64(CVTSS2SIr64v128, 1)
TEST_INPUTS(
    0x7f7fffff,  // std::numeric_limits<float>::max()
    0x00800000,  // std::numeric_limits<float>::min()
    0x3f800000,  // +1.0
    0xbf800000,  // -1.0
    0x00000000,  // +0.0
    0x80000000,  // -0.0
    0x3f000000,  // +0.5
    0xbf000000,  // -0.5
    0x47c34fc0)  // 99999.5

    movd xmm0, ARG1_32
    cvtss2si rax, xmm0
TEST_END_64

#if HAS_FEATURE_AVX

#if APPLE_SAFE_TESTS

TEST_BEGIN(VCVTSS2SIr32m32, 1)
TEST_INPUTS(
    0x7f7fffff,  // std::numeric_limits<float>::max()
    0x00800000,  // std::numeric_limits<float>::min()
    0x3f800000,  // +1.0
    0xbf800000,  // -1.0
    0x00000000,  // +0.0
    0x80000000,  // -0.0
    0x3f000000,  // +0.5
    0xbf000000,  // -0.5
    0x47c34fc0)  // 99999.5

    mov [rsp - 4], ARG1_32
    vcvtss2si eax, DWORD PTR [rsp - 4]
TEST_END

#endif  // APPLE_SAFE_TESTS

TEST_BEGIN(VCVTSS2SIr32v128, 1)
TEST_INPUTS(
    0x7f7fffff,  // std::numeric_limits<float>::max()
    0x00800000,  // std::numeric_limits<float>::min()
    0x3f800000,  // +1.0
    0xbf800000,  // -1.0
    0x00000000,  // +0.0
    0x80000000,  // -0.0
    0x3f000000,  // +0.5
    0xbf000000,  // -0.5
    0x47c34fc0)  // 99999.5

    movd xmm0, ARG1_32
    vcvtss2si eax, xmm0
TEST_END

#if APPLE_SAFE_TESTS

TEST_BEGIN_64(VCVTSS2SIr64m32, 1)
TEST_INPUTS(
    0x7f7fffff,  // std::numeric_limits<float>::max()
    0x00800000,  // std::numeric_limits<float>::min()
    0x3f800000,  // +1.0
    0xbf800000,  // -1.0
    0x00000000,  // +0.0
    0x80000000,  // -0.0
    0x3f000000,  // +0.5
    0xbf000000,  // -0.5
    0x47c34fc0)  // 99999.5

    mov [rsp - 4], ARG1_32
    vcvtss2si rax, DWORD PTR [rsp - 4]
TEST_END_64

#endif  // APPLE_SAFE_TESTS

TEST_BEGIN_64(VCVTSS2SIr64v128, 1)
TEST_INPUTS(
    0x7f7fffff,  // std::numeric_limits<float>::max()
    0x00800000,  // std::numeric_limits<float>::min()
    0x3f800000,  // +1.0
    0xbf800000,  // -1.0
    0x00000000,  // +0.0
    0x80000000,  // -0.0
    0x3f000000,  // +0.5
    0xbf000000,  // -0.5
    0x47c34fc0)  // 99999.5

    movd xmm0, ARG1_32
    vcvtss2si rax, xmm0
TEST_END_64

#endif  // HAS_FEATURE_AVX
