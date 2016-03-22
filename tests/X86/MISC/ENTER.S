/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN_64(ENTER_0_0, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 0, 0
TEST_END_64

TEST_BEGIN_64(ENTER_0_1, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 0, 1
TEST_END_64

TEST_BEGIN_64(ENTER_1_0, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 1, 0
TEST_END_64

TEST_BEGIN_64(ENTER_1_1, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 1, 1
TEST_END_64

TEST_BEGIN_64(ENTER_1_32, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 1, 32
TEST_END_64

TEST_BEGIN_64(ENTER_1_31, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 1, 31
TEST_END_64

TEST_BEGIN_64(ENTER_8_31, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 8, 31
TEST_END_64

TEST_BEGIN_64(ENTER_8_8, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 8, 8
TEST_END_64

TEST_BEGIN_64(ENTER_19_8, 1)
TEST_INPUTS(0)
    lea rsp, [rsp - 256]
    lea rbp, [rsp - 256]
    enter 19, 8
TEST_END_64
