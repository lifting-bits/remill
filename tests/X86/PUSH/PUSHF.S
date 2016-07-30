/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(PUSHF, 1)
TEST_INPUTS(
    0)
    .byte 0x66, 0x9C;  // PUSHF (word)
TEST_END

TEST_BEGIN_64(PUSHFQ_64, 1)
TEST_INPUTS(
    0)
    pushfq
TEST_END_64

TEST_BEGIN(PUSHF_POPF, 1)
TEST_INPUTS(
    0)
    .byte 0x66, 0x9C;  // PUSHF (word)
    .byte 0x66, 0x9D;  // POPF (word)
TEST_END

TEST_BEGIN_64(PUSHFQ_POPFQ_64, 1)
TEST_INPUTS(
    0)
    pushfq
    popfq
TEST_END_64

TEST_BEGIN_64(PUSHFQ_SET_CPUID_POPFQ_64, 1)
TEST_INPUTS(
    0)
    pushfq
    or QWORD PTR [rsp], 0x200000
    popfq
TEST_END_64

TEST_BEGIN_64(PUSHFQ_UNSET_CPUID_POPFQ_64, 1)
TEST_INPUTS(
    0)
    pushfq
    or QWORD PTR [rsp], 0x200000
    popfq
    pushfq
    xor QWORD PTR [rsp], 0x200000
    popfq
TEST_END_64
