/* Copyright 2016 Akshay Kumar (iit.akshay@gmail.com), all rights reserved. */

TEST_BEGIN_64(PACKSSWBr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    packsswb mm0, mm1
TEST_END_64

TEST_BEGIN_64(PACKSSWBr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    packsswb mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PACKSSWBv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    packsswb xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PACKSSWBv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    packsswb xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PACKSSDWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    packssdw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PACKSSDWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    packssdw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PACKSSDWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    packssdw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PACKSSDWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    packssdw xmm0, xmmword ptr [rsp]
TEST_END_64
