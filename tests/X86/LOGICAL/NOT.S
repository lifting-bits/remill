/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(NOTr8, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0x7F)

    mov eax, ARG1_32
    not al
TEST_END

TEST_BEGIN_64(NOTr8, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0x7F)

    mov r8, ARG1_64
    not r8b
TEST_END_64

TEST_BEGIN(NOTr16, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0x7F,
    0xFFFF,
    0x7FFF)

    not ARG1_16
TEST_END

TEST_BEGIN(NOTr32, 1)
TEST_INPUTS(
    0,
    1,
    0xFF,
    0x7F,
    0xFFFF,
    0x7FFF,
    0xFFFFFFFF,
    0x7FFFFFFF)

    not ARG1_32
TEST_END

TEST_BEGIN_64(NOTr64, 1)
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

    not ARG1_64
TEST_END_64
