/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(MULXedx, 2)
TEST_INPUTS(
    0, 0,
    1, 0x7FFF,
    1, 0xFFFF,
    0xFFFF, 0xFFFF,
    0xFFFFFFFF, 0xFFFF,
    0xFFFFFFFF, 0xFFFFFFFF)

    mov ecx, ARG1_32
    mov ebx, ARG2_32

    mulx edx, eax, ebx
TEST_END

TEST_BEGIN_64(MULXrdx, 2)
TEST_INPUTS(
    0, 1,
    0xFFFF, 0xFFFF,
    0xFFFFFFFF, 0xFFFF,
    0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0x7FFFFFFF,
    0x7FFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF)

    mov rcx, ARG1_64
    mov rbx, ARG2_64

    mulx rdx, rax, rbx
TEST_END_64
