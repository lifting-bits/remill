/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(SHRDr16r16i8_0, 2)
TEST_INPUTS(
    0, 0)
    mov eax, ARG1_32
    mov ebx, ARG2_32
    shrd ax, bx, 0  /* Basically a NOP */
TEST_END

TEST_BEGIN(SHRDr16r16i8_1, 2)
TEST_IGNORE_FLAGS(AF)
TEST_INPUTS(
    0, 0,
    1, 1,
    0xFF, 0xFF,
    0xFFFF, 0xFFFF,
    0, 0xFFFF,
    0xFFFF, 0)

    mov eax, ARG1_32
    mov ebx, ARG2_32
    shrd ax, bx, 1 /* Defines OF */
TEST_END

TEST_BEGIN(SHRDr16r16i8_16, 2)
TEST_IGNORE_FLAGS(OF AF)
TEST_INPUTS(
    0, 0,
    1, 1,
    0xFF, 0xFF,
    0xFFFF, 0xFFFF,
    0, 0xFFFF,
    0xFFFF, 0)

    mov eax, ARG1_32
    mov ebx, ARG2_32
    shrd ax, bx, 16
TEST_END

/* Not testing with count > size */

TEST_BEGIN(SHRDr32r32i8_0, 2)
TEST_INPUTS(
    0, 0)
    shrd ARG1_32, ARG2_32, 0  /* Basically a NOP */
TEST_END

TEST_BEGIN(SHRDr32r32i8_1, 2)
TEST_IGNORE_FLAGS(AF)
TEST_INPUTS(
    0, 0,
    1, 1,
    0xFF, 0xFF,
    0xFFFF, 0xFFFF,
    0, 0xFFFF,
    0xFFFF, 0,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xFFFFFFFF, 0)
    shrd ARG1_32, ARG2_32, 1
TEST_END

TEST_BEGIN(SHRDr32r32i8_31, 2)
TEST_IGNORE_FLAGS(OF AF)
TEST_INPUTS(
    0, 0,
    1, 1,
    0xFF, 0xFF,
    0xFFFF, 0xFFFF,
    0, 0xFFFF,
    0xFFFF, 0,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xFFFFFFFF, 0)
    shrd ARG1_32, ARG2_32, 31
TEST_END


TEST_BEGIN_64(SHRDr64r64i8_0, 2)
TEST_INPUTS(
    0, 0)
    shrd ARG1_64, ARG2_64, 0
TEST_END_64

TEST_BEGIN_64(SHRDr64r64i8_1, 2)
TEST_IGNORE_FLAGS(AF)
TEST_INPUTS(
    0, 0,
    1, 1,
    0xFF, 0xFF,
    0xFFFF, 0xFFFF,
    0, 0xFFFF,
    0xFFFF, 0,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xFFFFFFFF, 0)
    shrd ARG1_64, ARG2_64, 1
TEST_END_64

TEST_BEGIN_64(SHRDr64r64i8_31, 2)
TEST_IGNORE_FLAGS(OF AF)
TEST_INPUTS(
    0, 0,
    1, 1,
    0xFF, 0xFF,
    0xFFFF, 0xFFFF,
    0, 0xFFFF,
    0xFFFF, 0,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xFFFFFFFF, 0,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    0, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0)
    shrd ARG1_64, ARG2_64, 31
TEST_END_64
