/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(NEGr8, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0x7F)

    mov eax, ARG1_32
    neg al
TEST_END

TEST_BEGIN_64(NEGr8, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0x7F)

    mov r8, ARG1_64
    neg r8b
TEST_END_64

TEST_BEGIN(NEGr16, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0x7F,
    0xFFFF,
    0x7FFF)

    neg ARG1_16
TEST_END

TEST_BEGIN(NEGr32, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0x7F,
    0xFFFF,
    0x7FFF,
    0xFFFFFFFF,
    0x7FFFFFFF)

    neg ARG1_32
TEST_END

TEST_BEGIN_64(NEGr64, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0x7F,
    0xFFFF,
    0x7FFF,
    0xFFFFFFFF,
    0x7FFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0x7FFFFFFFFFFFFFFF)

    neg ARG1_64
TEST_END_64
