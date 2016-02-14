/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(LODSB, 1)
TEST_INPUTS(0)
#ifdef IN_TEST_GENERATOR
    .byte IF_64_BIT(0x48, ) 0x8d, 0x74, 0x24, 0xf8
#else
    lea rsi, [rsp - 8]
#endif
    lodsb
TEST_END

TEST_BEGIN(LODSW, 1)
TEST_INPUTS(0)
#ifdef IN_TEST_GENERATOR
    .byte IF_64_BIT(0x48, ) 0x8d, 0x74, 0x24, 0xf8
#else
    lea rsi, [rsp - 8]
#endif
    lodsw
TEST_END

TEST_BEGIN(LODSD, 1)
TEST_INPUTS(0)
#ifdef IN_TEST_GENERATOR
    .byte IF_64_BIT(0x48, ) 0x8d, 0x74, 0x24, 0xf8
#else
    lea rsi, [rsp - 8]
#endif
    lodsd
TEST_END

TEST_BEGIN_64(LODSQ, 1)
TEST_INPUTS(0)
    lea rsi, [rsp - 8]
    lodsq
TEST_END_64
