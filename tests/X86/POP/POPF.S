/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(POPF, 1)
TEST_INPUTS(
    0,
    0xfffffffffffafeff)
    push ARG1_16
    .byte 0x66, 0x9D;  // POPF (word)
TEST_END

TEST_BEGIN_64(POPFQ_64, 1)
TEST_INPUTS(
    0,
    0xfffffffffffafeff)
    push ARG1_64
    popfq
TEST_END_64
