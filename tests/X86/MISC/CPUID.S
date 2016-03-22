/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(CPUID, 2)
TEST_INPUTS(
    0x07, 0,
    0x05, 0,
    0x0A, 0,
    0x0B, 0,
    0x0C, 0,
    0x80000008, 0,
    0x0D, 0,
    0x0D, 1,
    0x0D, 31,
    0x0D, 32,
    0x0D, 63)

    mov eax, ARG1_32
    mov ecx, ARG2_32
    cpuid
TEST_END
