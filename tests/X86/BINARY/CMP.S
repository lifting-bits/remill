/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(CMPrr, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 1,
    0, 0xFFFFFFFF,
    0x10, 0, /* AF */
    0xFF, 0x11 /* PF */)

    cmp ARG1_32, ARG2_32
TEST_END

TEST_BEGIN_64(CMPrr, 2)
TEST_INPUTS(
    0, 1,
    1, 1,
    0, 0xFFFFFFFFFFFFFFFF)

    cmp ARG1_64, ARG2_64
TEST_END_64

TEST_BEGIN(CMPri, 1)
TEST_INPUTS(
    0,
    1)

    cmp ARG1_32, 1
TEST_END

TEST_BEGIN_64(CMPri, 1)
TEST_INPUTS(
    0,
    1)

    cmp ARG1_64, 1
TEST_END_64

