/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN_MEM(CMPXCHGm8r8al, 3)
TEST_IGNORE_FLAGS(AF)
TEST_INPUTS(
    0, 0, 0,
    0, 0, 1,
    0, 1, 0,
    0, 1, 1,
    1, 0, 0,
    1, 0, 1,
    1, 1, 1)

    mov eax, ARG1_32
    mov ebx, ARG2_32
    mov DWORD PTR [rsp - 4], ARG3_32
    cmpxchg BYTE PTR [rsp - 4], bl
TEST_END_MEM
