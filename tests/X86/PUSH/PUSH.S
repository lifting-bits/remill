/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN_64(PUSHrsp, 1)
TEST_INPUTS(0)
    push rsp
TEST_END_64

TEST_BEGIN_64(PUSHsp, 1)
TEST_INPUTS(0)
    push sp
TEST_END_64

TEST_BEGIN_64(PUSHmrsp64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 0x8]
    push QWORD PTR [rsp]
TEST_END_64


TEST_BEGIN_64(PUSHmrsp64offs, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 0x8]
    push QWORD PTR [rsp - 0x8]
TEST_END_64

TEST_BEGIN_64(PUSHmrsp16, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 0x8]
    push WORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(PUSHmrsp16offs, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 0x8]
    push WORD PTR [rsp - 0x8]
TEST_END_64

TEST_BEGIN_64(PUSHr16, 1)
TEST_INPUTS(
    0,
    0xFF,
    0xFFFF)
    mov rax, ARG1_64
    push ax
TEST_END_64

TEST_BEGIN_64(PUSHr64, 1)
TEST_INPUTS(
    0,
    0xFF,
    0xFFFF,
    0xFFFFFFFF,
    0xFFFFFFFFFFFFFFFF)
    push ARG1_64
TEST_END_64
