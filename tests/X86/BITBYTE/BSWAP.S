/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(BSWAPr32, 1)
TEST_INPUTS(
    0,
    1,
    0x80000000,
    0x80000001,
    0xFFFFFFFF,
    0x00000080,
    0x08000000,
    0xAABBCCDD)

    bswap ARG1_32
TEST_END

TEST_BEGIN_64(BSWAPr64, 1)
TEST_INPUTS(
    0,
    1,
    0x80000000,
    0x80000001,
    0xFFFFFFFF,
    0x00000080,
    0x08000000,
    0xAABBCCDD)

    bswap ARG1_64
TEST_END_64
