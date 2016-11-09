/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN_MEM_64(CMPXCHG8Bm64edxeax_0, 3)
TEST_INPUTS(
    0, 0, 0,
    0, 0, 1,
    0, 1, 0,
    0, 1, 1,
    1, 0, 0,
    1, 0, 1,
    1, 1, 0,
    1, 1, 1)

    data16 push 0
    push ARG1_16
    data16 push 0
    push ARG2_16

    push ARG3_64
    mov edx, 0
    pop rax

    mov ebx, 0
    mov ecx, 0
    not rbx
    not rcx
    cmpxchg8b QWORD PTR [rsp]
TEST_END_MEM_64

TEST_BEGIN_MEM_64(CMPXCHG8Bm64edxeax_1, 3)
TEST_INPUTS(
    0, 0, 0,
    0, 0, 1,
    0, 1, 0,
    0, 1, 1,
    1, 0, 0,
    1, 0, 1,
    1, 1, 0,
    1, 1, 1)

    data16 push 0
    push ARG1_16
    data16 push 0
    push ARG2_16

    push ARG3_64
    mov eax, 0
    pop rdx

    mov ebx, 0
    mov ecx, 0
    not rbx
    not rcx
    cmpxchg8b QWORD PTR [rsp]
TEST_END_MEM_64

