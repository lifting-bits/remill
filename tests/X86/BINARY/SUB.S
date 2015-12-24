/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(SUBrr, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 1,
    0, 0xFFFFFFFF,
    0x10, 0, /* AF */
    0xFF, 0x11 /* PF */)

    sub ARG1_32, ARG2_32
TEST_END

TEST_BEGIN_64(SUBrr, 2)
TEST_INPUTS(
    0, 1,
    1, 1,
    0, 0xFFFFFFFFFFFFFFFF)

    sub ARG1_64, ARG2_64
TEST_END_64

TEST_BEGIN(SUBri, 1)
TEST_INPUTS(
    0,
    1)

    sub ARG1_32, 1
TEST_END

TEST_BEGIN_64(SUBri, 1)
TEST_INPUTS(
    0,
    1)

    sub ARG1_64, 1
TEST_END_64

