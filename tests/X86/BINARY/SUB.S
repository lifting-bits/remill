/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(SUBal, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF)

    mov eax, ARG1_32
    sub al, 1
TEST_END

TEST_BEGIN(SUBax, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF)

    mov eax, ARG1_32
    sub ax, 1
TEST_END

TEST_BEGIN(SUBeax, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF)

    mov eax, ARG1_32
    sub eax, 1
TEST_END

TEST_BEGIN(SUBr8i8, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF)

    mov ebx, ARG1_32
    sub bl, 1
TEST_END

TEST_BEGIN_64(SUBr8u8, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF)

    mov r8, ARG1_64
    sub r8b, 0x7F
TEST_END_64

TEST_BEGIN_64(SUBr8s8, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF)

    mov r8, ARG1_64
    sub r8b, 0xFF /* Sign-extended to 64-bits */
TEST_END_64

TEST_BEGIN(SUBr8r8, 2)
TEST_INPUTS(
    0, 0,
    1, 0,
    0xFF, 1,
    0x7F, 1,
    0x7F, 0xFF,
    0xFF, 0xFF)

    mov ebx, ARG1_32
    mov eax, ARG2_32
    sub bl, al
TEST_END

TEST_BEGIN_64(SUBr8r8, 1)
TEST_INPUTS(
    0, 0,
    1, 0,
    0xFF, 1,
    0x7F, 1,
    0x7F, 0xFF,
    0xFF, 0xFF)

    mov r8, ARG1_64
    mov r9, ARG2_64
    sub r9b, r8b
TEST_END_64

TEST_BEGIN(SUBr16u8, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF)

    mov ebx, ARG1_32
    sub bx, 0x7F
TEST_END

TEST_BEGIN(SUBr16s8, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF)

    mov ebx, ARG1_32
    sub bx, 0xFF /* Sign-extended to 16-bits */
TEST_END

TEST_BEGIN(SUBr16i16, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF)

    mov ebx, ARG1_32
    sub bx, 0xFFFF
TEST_END

TEST_BEGIN(SUBr16r16, 2)
TEST_INPUTS(
    0, 0,
    1, 0,
    0xFF, 1,
    0x7F, 1,
    0x7F, 0xFF,
    0xFF, 0xFF,
    0x7FFF, 1,
    0x7FFF, 0xFFFF,
    0xFFFF, 0xFFFF)

    mov ebx, ARG1_32
    mov edx, ARG2_32
    sub bx, dx
TEST_END

TEST_BEGIN(SUBr32u8, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF)

    mov ebx, ARG1_32
    sub ebx, 0x7F
TEST_END

TEST_BEGIN(SUBr32s8, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF)

    mov ebx, ARG1_32
    sub ebx, 0xFF
TEST_END

TEST_BEGIN(SUBr32i32, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF)

    mov ebx, ARG1_32
    sub ebx, 0x7FFFFFFF
TEST_END

TEST_BEGIN(SUBr32r32, 2)
TEST_INPUTS(
    0, 0, /* ZF */
    1, 0,
    0xFFFFFFFF, 1, /* OF, CF */
    0xFFFFFFFF, 0xFFFFFFFF, /* OF */
    0x7FFFFFFF, 1, /* SF */
    0, 0x10, /* AF */
    0x7F, 0x10 /* PF */)

    sub ARG1_32, ARG2_32
TEST_END

TEST_BEGIN_64(SUBr64u8, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF,
    0x7FFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF)

    sub ARG1_64, 0x7F
TEST_END_64

TEST_BEGIN_64(SUBr64s8, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF,
    0x7FFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF)

    sub ARG1_64, 0xFF /* Sign-extended */
TEST_END_64

TEST_BEGIN_64(SUBr64u32, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF,
    0x7FFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF)

    sub ARG1_64, 0x7FFFFFFF
TEST_END_64

TEST_BEGIN_64(SUBr64s32, 1)
TEST_INPUTS(
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF,
    0x7FFFFFFF,
    0xFFFFFFFF,
    0x7FFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF)

    .byte 0x48;  /* REX.W */
    sub ARG1_32, 0xFFFFFFFF /* Sign-extended */
TEST_END_64

TEST_BEGIN_64(SUBr64r64, 2)
TEST_INPUTS(
    0, 0, /* ZF */
    1, 0,
    0xFFFFFFFF, 1, /* OF, CF */
    0xFFFFFFFF, 0xFFFFFFFF, /* OF */
    0x7FFFFFFF, 1, /* SF */
    0, 0x10, /* AF */
    0x7F, 0x10, /* PF */
    0x7FFFFFFFFFFFFFFF, 1,
    0x7FFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF,
    0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF)

    sub ARG1_64, ARG2_64
TEST_END_64
