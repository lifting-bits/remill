/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(ADDrr, 2)
    TEST_INSTR( add ARG1_32, ARG2_32 )
TEST_END

TEST_BEGIN_64(ADDrr, 2)
    TEST_INSTR( add ARG1_64, ARG2_64 )
TEST_END_64

TEST_BEGIN(ADDri, 1)
    TEST_INSTR( add ARG1_32, 1 )
TEST_END

TEST_BEGIN_64(ADDri, 1)
    TEST_INSTR( add ARG1_64, 1 )
TEST_END_64

