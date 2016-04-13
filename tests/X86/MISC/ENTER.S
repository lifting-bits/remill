/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN_64(ENTER_0_0_64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 0, 0
TEST_END_64

TEST_BEGIN_64(ENTER_0_1_64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 0, 1
TEST_END_64

TEST_BEGIN_64(ENTER_1_0_64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 1, 0
TEST_END_64

TEST_BEGIN_64(ENTER_1_1_64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 1, 1
TEST_END_64

TEST_BEGIN_64(ENTER_1_32_64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 1, 32
TEST_END_64

TEST_BEGIN_64(ENTER_1_31_64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 1, 31
TEST_END_64

TEST_BEGIN_64(ENTER_8_31_64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 8, 31
TEST_END_64

TEST_BEGIN_64(ENTER_8_8_64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 8, 8
TEST_END_64

TEST_BEGIN_64(ENTER_19_8_64, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 19, 8
TEST_END_64
