/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#if APPLE_SAFE_TESTS

TEST_BEGIN(CVTPI2PDv128m64, 2)
TEST_INPUTS(
    0x0, 0x0,
    0xFFFFFFFF, 0x0,
    0x0, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF,
    0x41414141, 0xABABABAB)  // 99999.5

    mov DWORD PTR [rsp - 4], ARG1_32
    mov DWORD PTR [rsp - 8], ARG2_32
    cvtpi2pd xmm0, QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(CVTPI2PDv128v64, 2)
TEST_INPUTS(
    0x0, 0x0,
    0xFFFFFFFF, 0x0,
    0x0, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF,
    0x41414141, 0xABABABAB)  // 99999.5

    mov DWORD PTR [rsp - 4], ARG1_32
    mov DWORD PTR [rsp - 8], ARG2_32
    movq mm0, [rsp - 8]
    cvtpi2pd xmm0, mm0
TEST_END

// TODO(pag): Test CVTPI2PD_XMMpd_MMXq

#endif  // APPLE_SAFE_TESTS
