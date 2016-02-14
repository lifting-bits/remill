/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(CMPSB, 1)
TEST_INPUTS(0)
#ifdef IN_TEST_GENERATOR
    .byte IF_64_BIT(0x48, ) 0x8d, 0x7c, 0x24, 0xf8
    .byte IF_64_BIT(0x48, ) 0x8d, 0x74, 0x24, 0xf8
#else
    lea rdi, [rsp - 8]
    lea rsi, [rsp - 8]
#endif
    cmpsb
TEST_END

TEST_BEGIN(CMPSW, 1)
TEST_INPUTS(0)
#ifdef IN_TEST_GENERATOR
    .byte IF_64_BIT(0x48, ) 0x8d, 0x7c, 0x24, 0xf8
    .byte IF_64_BIT(0x48, ) 0x8d, 0x74, 0x24, 0xf8
#else
    lea rdi, [rsp - 8]
    lea rsi, [rsp - 8]
#endif
    cmpsw
TEST_END

TEST_BEGIN(CMPSD, 1)
TEST_INPUTS(0)
#ifdef IN_TEST_GENERATOR
    .byte IF_64_BIT(0x48, ) 0x8d, 0x7c, 0x24, 0xf8
    .byte IF_64_BIT(0x48, ) 0x8d, 0x74, 0x24, 0xf8
#else
    lea rdi, [rsp - 8]
    lea rsi, [rsp - 8]
#endif
    cmpsd
TEST_END

TEST_BEGIN_64(CMPSQ, 1)
TEST_INPUTS(0)
    lea rdi, [rsp - 8]
    lea rsi, [rsp - 8]
    cmpsq
TEST_END_64
