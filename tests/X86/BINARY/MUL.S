/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(MULal, 2)
TEST_IGNORE_FLAGS(ZF AF PF SF)
TEST_INPUTS(
    0, 0,
    0x7F, 0x7F,
    0xFF, 0x7F,
    0xFF, 0xFF)

    mov eax, ARG1_32
    mov ebx, ARG2_32

    imul bl
TEST_END

TEST_BEGIN_64(MULal, 2)
TEST_IGNORE_FLAGS(ZF AF PF SF)
TEST_INPUTS(
    0, 0,
    0x7F, 0x7F,
    0xFF, 0x7F,
    0xFF, 0xFF)

    mov rax, ARG1_64
    mov r8, ARG2_64

    imul r8b
TEST_END_64

TEST_BEGIN(MULax, 2)
TEST_IGNORE_FLAGS(ZF AF PF SF)
TEST_INPUTS(
    0, 0,
    1, 0x7FFF,
    1, 0xFFFF,
    0xFFFF, 0xFFFF)

    mov eax, ARG1_32
    mov ebx, ARG2_32

    imul bx
TEST_END

TEST_BEGIN(MULeax, 2)
TEST_IGNORE_FLAGS(ZF AF PF SF)
TEST_INPUTS(
    0, 0,
    1, 0x7FFF,
    1, 0xFFFF,
    0xFFFF, 0xFFFF,
    0xFFFFFFFF, 0xFFFF,
    0xFFFFFFFF, 0xFFFFFFFF)

    mov eax, ARG1_32
    mov ebx, ARG2_32

    imul ebx
TEST_END

TEST_BEGIN_64(MULrax, 2)
TEST_IGNORE_FLAGS(ZF AF PF SF)
TEST_INPUTS(
    0, 1,
    0xFFFF, 0xFFFF,
    0xFFFFFFFF, 0xFFFF,
    0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0x7FFFFFFF,
    0x7FFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF)

    mov rax, ARG1_64
    mov rbx, ARG2_64

    imul rbx
TEST_END_64
