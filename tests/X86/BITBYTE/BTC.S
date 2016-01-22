/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(BTCr16i8, 1)
TEST_INPUTS(
    0,
    1)

    btc ARG1_16, 1
TEST_END

TEST_BEGIN(BTCr16r16, 2)
TEST_INPUTS(
    0, 0,
    1, 0,
    0xFFFF, 16,
    0xFFFF, 15,
    0xFFFE, 16)

    btc ARG1_16, ARG2_16
TEST_END

TEST_BEGIN(BTCm16r16, 1)
TEST_INPUTS(
    0,
    1,
    15,
    16,
    31,
    32,
    63)
#ifdef IN_TEST_GENERATOR
    .byte IF_64_BIT(0x48, ) 0x8D, 0x74, 0x24, 0xF8
    .byte 0xC7, 0x44, 0x24, 0xF8, 0x00, 0xFF, 0x00, 0xFF
    .byte 0xC7, 0x44, 0x24, 0xFC, 0x00, 0xFF, 0x00, 0xFF
    .byte 0x66, 0x0F, 0xBB, 0x3E
#else
    lea ARG2_ADDR, [SP_ADDR - 8]
    mov DWORD PTR [SP_ADDR - 8], 0xFF00FF00
    mov DWORD PTR [SP_ADDR - 4], 0xFF00FF00
    btc WORD PTR [ARG2_ADDR], ARG1_16
#endif
TEST_END

TEST_BEGIN(BTCr32i8, 1)
TEST_INPUTS(
    0,
    1)

    btc ARG1_32, 1
TEST_END

TEST_BEGIN(BTCm32r32, 1)
TEST_INPUTS(
    0,
    1,
    15,
    16,
    31,
    32,
    63)
#ifdef IN_TEST_GENERATOR
    .byte IF_64_BIT(0x48, ) 0x8D, 0x74, 0x24, 0xF8
    .byte 0xC7, 0x44, 0x24, 0xF8, 0x00, 0xFF, 0x00, 0xFF
    .byte 0xC7, 0x44, 0x24, 0xFC, 0x00, 0xFF, 0x00, 0xFF
    .byte 0x0F, 0xBB, 0x3E
#else
    lea ARG2_ADDR, [SP_ADDR - 8]
    mov DWORD PTR [SP_ADDR - 8], 0xFF00FF00
    mov DWORD PTR [SP_ADDR - 4], 0xFF00FF00
    btc DWORD PTR [ARG2_ADDR], ARG1_32
#endif
TEST_END

TEST_BEGIN(BTCr32r32, 2)
TEST_INPUTS(
    0, 0,
    1, 0,
    0xFFFF, 16,
    0xFFFF, 15,
    0xFFFE, 16,
    0xFFFFFFFF, 32,
    0xFFFFFFFF, 31,
    0xFFFFFFFE, 32)

    btc ARG1_32, ARG2_32
TEST_END

TEST_BEGIN_64(BTCr32i8, 1)
TEST_INPUTS(
    0,
    1)

    btc ARG1_64, 1
TEST_END_64

TEST_BEGIN_64(BTCr64r64, 2)
TEST_INPUTS(
    0, 0,
    1, 0,
    0xFFFF, 16,
    0xFFFF, 15,
    0xFFFE, 16,
    0xFFFFFFFF, 32,
    0xFFFFFFFF, 31,
    0xFFFFFFFE, 32,
    0xFFFFFFFFFFFFFFFE, 64,
    0xFFFFFFFFFFFFFFFF, 63,
    0xFFFFFFFFFFFFFFFE, 64)

    btc ARG1_64, ARG2_64
TEST_END_64

TEST_BEGIN_64(BTCm64r64, 1)
TEST_INPUTS(
    0,
    1,
    15,
    16,
    31,
    32,
    63)

    lea ARG2_ADDR, [SP_ADDR - 8]
    mov DWORD PTR [SP_ADDR - 8], 0xFF00FF00
    mov DWORD PTR [SP_ADDR - 4], 0xFF00FF00
    btc QWORD PTR [ARG2_ADDR], ARG1_64
TEST_END_64
