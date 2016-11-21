/* Copyright 2016 Akshay Kumar (iit.akshay@gmail.com), all rights reserved. */

TEST_BEGIN_64(PUNPCKHBWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    punpckhbw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PUNPCKHBWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    punpckhbw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PUNPCKHBWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    punpckhbw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PUNPCKHBWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    punpckhbw xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PUNPCKHWDr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    punpckhwd mm0, mm1
TEST_END_64

TEST_BEGIN_64(PNPCKHWDr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    punpckhwd mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PNPCKHWDv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    punpckhwd xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PNPCKHWDv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    punpckhwd xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PUNPCKHDQr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    punpckhdq mm0, mm1
TEST_END_64

TEST_BEGIN_64(PUNPCKHDQr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    punpckhdq mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PUNPCKHDQv128v128_04, 1)
TEST_INPUTS()
    punpckhdq xmm0, xmm4
TEST_END_64

TEST_BEGIN_64(PUNPCKHDQv128v128_40, 1)
TEST_INPUTS()
    punpckhdq xmm4, xmm0
TEST_END_64

TEST_BEGIN_64(PUNPCKHDQv128m128_0, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    push ARG2_64
    punpckhdq xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PUNPCKHDQv128m128_4, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    push ARG2_64
    punpckhdq xmm4, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PUNPCKHQDQv128v128_04, 1)
TEST_INPUTS()
    punpckhqdq xmm0, xmm4
TEST_END_64

TEST_BEGIN_64(PUNPCKHQDQv128v128_40, 1)
TEST_INPUTS()
    punpckhqdq xmm4, xmm0
TEST_END_64

TEST_BEGIN_64(PUNPCKLQDQv128v128_04, 1)
TEST_INPUTS()
    punpcklqdq xmm0, xmm4
TEST_END_64

TEST_BEGIN_64(PUNPCKLQDQv128v128_40, 1)
TEST_INPUTS()
    punpcklqdq xmm4, xmm0
TEST_END_64

TEST_BEGIN_64(PUNPCKLBWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    punpcklbw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PUNPCKLBWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    punpcklbw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PUNPCKLBWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    punpcklbw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PUNPCKLBWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    punpcklbw xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PUNPCKLWDr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    punpcklwd mm0, mm1
TEST_END_64

TEST_BEGIN_64(PUNPCKLWDr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    punpcklwd mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PUNPCKLWDv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    punpcklwd xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PUNPCKLWDv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    punpcklwd xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PUNPCKLDQr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    punpckldq mm0, mm1
TEST_END_64

TEST_BEGIN_64(PUNPCKLDQr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    punpckldq mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PUNPCKLDQv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    punpckldq xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PUNPCKLDQv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    punpckldq xmm0, xmmword ptr [rsp]
TEST_END_64
