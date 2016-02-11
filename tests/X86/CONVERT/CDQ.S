/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN_64(CDQ, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0x80,
    0x7F00,
    0x8000,
    0xFF00,
    0xFF00FF00,
    0x00FF00FF,
    0x7F00FF00,
    0x80FF00FF,
    0xFFFFFFFF00000000,
    0xFFFFFFF080000000)
    mov rax, ARG1_64
    cdq
TEST_END_64
