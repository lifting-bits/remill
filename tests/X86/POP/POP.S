/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN_64(POPrsp, 1)
TEST_INPUTS(0)
    push rsp
    pop rsp
TEST_END_64

TEST_BEGIN_64(POPsp, 1)
TEST_INPUTS(0)
    push sp
    pop sp
TEST_END_64

TEST_BEGIN_64(POPmrsp64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 16]
    pop QWORD PTR [rsp]
TEST_END_64


TEST_BEGIN_64(POPmrsp64offs, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 16]
    pop QWORD PTR [rsp - 0x8]
TEST_END_64

TEST_BEGIN_64(POPmrsp16, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 16]
    pop WORD PTR [rsp]
TEST_END_64

TEST_BEGIN_64(POPmrsp16offs, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 16]
    pop WORD PTR [rsp - 0x8]
TEST_END_64

TEST_BEGIN_64(POPr16, 1)
TEST_INPUTS(
    0,
    0xFF,
    0xFFFF)
    lea rsp, [rsp - 16]
    mov rax, ARG1_64
    pop ax
TEST_END_64

TEST_BEGIN_64(POPr64, 1)
TEST_INPUTS(
    0,
    0xFF,
    0xFFFF,
    0xFFFFFFFF,
    0xFFFFFFFFFFFFFFFF)
    lea rsp, [rsp - 16]
    pop ARG1_64
TEST_END_64
