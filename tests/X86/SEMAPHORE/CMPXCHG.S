/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN_MEM(CMPXCHGm8r8al, 3)
TEST_INPUTS(
    0, 0, 0,
    0, 0, 1,
    0, 1, 0,
    0, 1, 1,
    1, 0, 0,
    1, 0, 1,
    1, 1, 0,
    1, 1, 1)

    mov eax, ARG1_32
    mov ebx, ARG2_32
    mov DWORD PTR [rsp - 4], ARG3_32
    cmpxchg BYTE PTR [rsp - 4], bl
TEST_END_MEM

TEST_BEGIN(CMPXCHGr8r8al, 3)
TEST_INPUTS(
    0, 0, 0,
    0, 0, 1,
    0, 1, 0,
    0, 1, 1,
    1, 0, 0,
    1, 0, 1,
    1, 1, 0,
    1, 1, 1)

    mov eax, ARG1_32
    mov ebx, ARG2_32
    cmpxchg ARG3_8, bl
TEST_END

TEST_BEGIN_MEM(CMPXCHGm16r16ax, 3)
TEST_INPUTS(
    0, 0, 0,
    0, 0, 1,
    0, 1, 0,
    0, 1, 1,
    1, 0, 0,
    1, 0, 1,
    1, 1, 0,
    1, 1, 1)

    mov eax, ARG1_32
    mov ebx, ARG2_32
    mov DWORD PTR [rsp - 4], ARG3_32
    cmpxchg WORD PTR [rsp - 4], bx
TEST_END_MEM

TEST_BEGIN(CMPXCHGr16r16ax, 3)
TEST_INPUTS(
    0, 0, 0,
    0, 0, 1,
    0, 1, 0,
    0, 1, 1,
    1, 0, 0,
    1, 0, 1,
    1, 1, 0,
    1, 1, 1)

    mov eax, ARG1_32
    mov ebx, ARG2_32
    cmpxchg ARG3_16, bx
TEST_END

TEST_BEGIN_MEM(CMPXCHGm32r32eax, 3)
TEST_INPUTS(
    0, 0, 0,
    0, 0, 1,
    0, 1, 0,
    0, 1, 1,
    1, 0, 0,
    1, 0, 1,
    1, 1, 0,
    1, 1, 1)

    mov eax, ARG1_32
    mov ebx, ARG2_32
    mov DWORD PTR [rsp - 4], ARG3_32
    cmpxchg DWORD PTR [rsp - 4], ebx
TEST_END_MEM

TEST_BEGIN(CMPXCHGr32r32eax, 3)
TEST_INPUTS(
    0, 0, 0,
    0, 0, 1,
    0, 1, 0,
    0, 1, 1,
    1, 0, 0,
    1, 0, 1,
    1, 1, 0,
    1, 1, 1)

    mov eax, ARG1_32
    mov ebx, ARG2_32
    cmpxchg ARG3_32, ebx
TEST_END

TEST_BEGIN_MEM_64(CMPXCHGm64r64rax, 3)
TEST_INPUTS(
    0, 0, 0,
    0, 0, 1,
    0, 1, 0,
    0, 1, 1,
    1, 0, 0,
    1, 0, 1,
    1, 1, 0,
    1, 1, 1)

    mov eax, ARG1_32
    mov ebx, ARG2_32
    mov QWORD PTR [rsp - 8], ARG3_64
    cmpxchg QWORD PTR [rsp - 8], rbx
TEST_END_MEM_64

TEST_BEGIN_64(CMPXCHGr64r64rax, 3)
TEST_INPUTS(
    0, 0, 0,
    0, 0, 1,
    0, 1, 0,
    0, 1, 1,
    1, 0, 0,
    1, 0, 1,
    1, 1, 0,
    1, 1, 1)

    mov eax, ARG1_32
    mov ebx, ARG2_32
    cmpxchg ARG3_64, rbx
TEST_END_64

