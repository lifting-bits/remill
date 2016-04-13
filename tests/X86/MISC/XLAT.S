/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN_64(XLAT_64, 1)
TEST_INPUTS(
    0,
    1,
    32,
    64,
    127,
    128,
    255,
    256)

    mov rax, ARG1_64
    lea rbx, [rsp - 256]
    xlatb
TEST_END_64
