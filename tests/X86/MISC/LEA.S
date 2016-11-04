/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN_MEM(LEA, 3)
TEST_INPUTS(
    0, 0, 0,
    0xFF, 0xFF, 0xFF,
    0xFF, 0, 0xFF,
    0xFF, 0xFF, 0)
    // lea ARG1_32, [ARG2_32 + 2 * ARG3_32 + 1]
    .byte IF_64_BIT(0x67,) 0x8D, 0x7C, 0x56, 0x01 ;
TEST_END_MEM

TEST_BEGIN_MEM_64(LEA_64, 3)
TEST_INPUTS(
    0, 0, 0,
    0xFF, 0xFF, 0xFF,
    0xFF, 0, 0xFF,
    0xFF, 0xFF, 0)
    lea ARG1_64, [ARG2_64 + 2 * ARG3_64 + 1]
TEST_END_MEM_64
