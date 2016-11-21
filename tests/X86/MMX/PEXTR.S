/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

TEST_BEGIN_64(PEXTRB_0, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrb eax, xmm0, 0
TEST_END_64

TEST_BEGIN_64(PEXTRB_1, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrb eax, xmm0, 1
TEST_END_64

TEST_BEGIN_64(PEXTRB_7, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrb eax, xmm0, 7
TEST_END_64

TEST_BEGIN_64(PEXTRB_15, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrb eax, xmm0, 15
TEST_END_64

TEST_BEGIN_64(PEXTRB_16, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrb eax, xmm0, 16
TEST_END_64


TEST_BEGIN_64(PEXTRW_0, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrw eax, xmm0, 0
TEST_END_64

TEST_BEGIN_64(PEXTRW_1, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrw eax, xmm0, 1
TEST_END_64

TEST_BEGIN_64(PEXTRW_2, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrw eax, xmm0, 2
TEST_END_64

TEST_BEGIN_64(PEXTRW_3, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrw eax, xmm0, 3
TEST_END_64

TEST_BEGIN_64(PEXTRW_7, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrw eax, xmm0, 7
TEST_END_64

TEST_BEGIN_64(PEXTRW_8, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrw eax, xmm0, 8
TEST_END_64




TEST_BEGIN_64(PEXTRD_0, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrd eax, xmm0, 0
TEST_END_64

TEST_BEGIN_64(PEXTRD_1, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrd eax, xmm0, 1
TEST_END_64

TEST_BEGIN_64(PEXTRD_2, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrd eax, xmm0, 2
TEST_END_64

TEST_BEGIN_64(PEXTRD_3, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrd eax, xmm0, 3
TEST_END_64

TEST_BEGIN_64(PEXTRD_4, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrd eax, xmm0, 4
TEST_END_64





TEST_BEGIN_64(PEXTRQ_1, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrq rax, xmm0, 1
TEST_END_64

TEST_BEGIN_64(PEXTRQ_2, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrq rax, xmm0, 2
TEST_END_64

TEST_BEGIN_64(PEXTRQ_3, 2)
TEST_INPUTS_MMX_2()
    push ARG1_64
    push ARG2_64
    movdqu xmm0, xmmword ptr [rsp]
    pextrq rax, xmm0, 3
TEST_END_64
