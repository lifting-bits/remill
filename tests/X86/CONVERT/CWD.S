/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(CWD, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0x80,
    0x7F00,
    0x8000,
    0xFF00,
    0xFF00FF00,
    0x00FF00FF)
    mov eax, ARG1_32
    cwd
TEST_END
