/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(ADDrr, 2)
TEST_INPUTS(
    0, 0, /* ZF */
    0xFFFFFFFF, 1, /* OF, CF */
    0xFFFFFFFF, 0xFFFFFFFF, /* OF */
    0x7FFFFFFF, 1, /* SF */
    0, 0x10, /* AF */
    0x7F, 0x10 /* PF */)

    add ARG1_32, ARG2_32
TEST_END

TEST_BEGIN_64(ADDrr, 2)
TEST_INPUTS(
    0xFFFFFFFFFFFFFFFF, 1, /* OF, CF */
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, /* OF */
    0x7FFFFFFFFFFFFFFF, 1 /* SF */)

    add ARG1_64, ARG2_64
TEST_END_64

TEST_BEGIN(ADDri, 1)
TEST_INPUTS(
    0,
    1)

    add ARG1_32, 1
TEST_END

TEST_BEGIN_64(ADDri, 1)
TEST_INPUTS(
    0,
    1)

    add ARG1_64, 1
TEST_END_64

