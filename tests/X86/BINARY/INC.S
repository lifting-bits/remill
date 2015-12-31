/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(INCr8, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF)

    mov eax, ARG1_32
    inc al
TEST_END

TEST_BEGIN_64(INCr8, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF)

    inc ARG1_8
TEST_END_64

TEST_BEGIN(INCr16, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF)

    inc ARG1_16
TEST_END

TEST_BEGIN(INCr32, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF)

    inc ARG1_32
TEST_END

TEST_BEGIN_64(INCr64, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF,
    0x7FFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF)

    inc ARG1_64
TEST_END_64
