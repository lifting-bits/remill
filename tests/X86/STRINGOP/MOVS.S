/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(MOVSB, 1)
TEST_INPUTS(0)
#ifdef IN_TEST_GENERATOR
    .byte IF_64_BIT(0x48, ) 0x8d, 0x7c, 0x24, 0xf8
    .byte IF_64_BIT(0x48, ) 0x8d, 0x74, 0x24, 0xf8
#else
    lea rdi, [rsp - 8]
    lea rsi, [rsp - 8]
#endif
    .byte 0xa4
TEST_END

TEST_BEGIN(MOVSW, 1)
TEST_INPUTS(0)
#ifdef IN_TEST_GENERATOR
    .byte IF_64_BIT(0x48, ) 0x8d, 0x7c, 0x24, 0xf8
    .byte IF_64_BIT(0x48, ) 0x8d, 0x74, 0x24, 0xf8
#else
    lea rdi, [rsp - 8]
    lea rsi, [rsp - 8]
#endif
    .byte 0x66, 0xa5
TEST_END

TEST_BEGIN(MOVSD, 1)
TEST_INPUTS(0)
#ifdef IN_TEST_GENERATOR
    .byte IF_64_BIT(0x48, ) 0x8d, 0x7c, 0x24, 0xf8
    .byte IF_64_BIT(0x48, ) 0x8d, 0x74, 0x24, 0xf8
#else
    lea rdi, [rsp - 8]
    lea rsi, [rsp - 8]
#endif
    .byte 0xa5
TEST_END

TEST_BEGIN_64(MOVSQ_64, 1)
TEST_INPUTS(0)
    lea rdi, [rsp - 8]
    lea rsi, [rsp - 8]
    .byte 0x48, 0xa5
TEST_END_64
