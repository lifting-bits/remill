/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN(PSHUFDv128v128i8_03, 1)
TEST_INPUTS(
    0)

    pshufd xmm4, xmm0, 0x00
    pshufd xmm5, xmm1, 0x11
    pshufd xmm6, xmm2, 0x22
    pshufd xmm7, xmm3, 0x33
TEST_END

TEST_BEGIN(PSHUFDv128v128i8_47, 1)
TEST_INPUTS(
    0)

    pshufd xmm4, xmm0, 0x44
    pshufd xmm5, xmm1, 0x55
    pshufd xmm6, xmm2, 0x66
    pshufd xmm7, xmm3, 0x77
TEST_END

TEST_BEGIN(PSHUFDv128v128i8_8b, 1)
TEST_INPUTS(
    0)

    pshufd xmm4, xmm0, 0x88
    pshufd xmm5, xmm1, 0x99
    pshufd xmm6, xmm2, 0xaa
    pshufd xmm7, xmm3, 0xbb
TEST_END

TEST_BEGIN(PSHUFDv128v128i8_cf, 1)
TEST_INPUTS(
    0)

    pshufd xmm4, xmm0, 0xcc
    pshufd xmm5, xmm1, 0xdd
    pshufd xmm6, xmm2, 0xee
    pshufd xmm7, xmm3, 0xff
TEST_END
