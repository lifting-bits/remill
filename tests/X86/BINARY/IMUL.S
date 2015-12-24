/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(IMULax_r8, 2)
TEST_IGNORE_FLAGS(ZF AF PF)
TEST_INPUTS(
    0, 0,
    0xFF, 0xFF)

    mov ax, ARG1_16
    mov bx, ARG2_16

    imul bl
TEST_END

TEST_BEGIN(IMULax_r16, 2)
TEST_IGNORE_FLAGS(ZF AF PF)
TEST_INPUTS(
    0, 0,
    0xFFFF, 0xFFFF)

    mov ax, ARG1_16
    mov bx, ARG2_16

    imul bx
TEST_END
