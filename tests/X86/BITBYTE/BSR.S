/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(BSRr16r16, 1)
TEST_IGNORE_FLAGS(CF OF SF AF PF)
TEST_INPUTS(
    0,
    1,
    0x8000,
    0x8001,
    0xFFFF,
    0x0080,
    0x0800)

    mov eax, ARG1_32
    bsr dx, ax
TEST_END

TEST_BEGIN(BSRr32r32, 1)
TEST_IGNORE_FLAGS(CF OF SF AF PF)
TEST_INPUTS(
    0,
    1,
    0x80000000,
    0x80000001,
    0xFFFFFFFF,
    0x00000080,
    0x08000000)

    mov eax, ARG1_32
    bsr edx, eax
TEST_END

TEST_BEGIN_64(BSRr64r64, 1)
TEST_IGNORE_FLAGS(CF OF SF AF PF)
TEST_INPUTS(
    0,
    1,
    0x8000000000000000,
    0x8000000000000001,
    0xFFFFFFFFFFFFFFFF,
    0x0000000000000080,
    0x0800000000000000)

    mov rax, ARG1_64
    bsr rdx, rax
TEST_END_64
