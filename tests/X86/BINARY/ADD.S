/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(ADDrr_32)
    mov eax, 1
    mov ebx, -1
    TEST_INSTR( add eax, ebx )
TEST_END(ADDrr_32)

TEST_BEGIN_64(ADDrr_64)
    mov rax, 1
    mov rbx, -1
    TEST_INSTR( add rax, rbx )
TEST_END_64(ADDrr_64)

TEST_BEGIN(ADDri_32)
    mov eax, -1
    TEST_INSTR( add eax, 1 )
TEST_END(ADDri_32)

TEST_BEGIN(ADDri_64)
    mov rax, -1
    TEST_INSTR( add rax, 1 )
TEST_END(ADDri_32)
