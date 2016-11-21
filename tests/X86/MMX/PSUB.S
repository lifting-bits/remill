/* Copyright 2016 Akshay Kumar (iit.akshay@gmail.com), all rights reserved. */

TEST_BEGIN_64(PSUBBr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    psubb mm0, mm1
TEST_END_64

TEST_BEGIN_64(PSUBBr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    psubb mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSUBBv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    psubb xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PSUBBv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    psubb xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSUBWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    psubw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PSUBWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    psubw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSUBWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    psubw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PSUBWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    psubw xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSUBDr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    psubd mm0, mm1
TEST_END_64

TEST_BEGIN_64(PSUBDr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    psubb mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSUBDv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    psubd xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PSUBDv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    psubb xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSUBUSBr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    psubusb mm0, mm1
TEST_END_64

TEST_BEGIN_64(PSUBUSBr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    psubusb mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSUBUSBv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    psubusb xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PSUBUSBv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    psubusb xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSUBUSWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    psubusw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PSUBUSWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    psubusw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PSUBUSWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    psubusw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PSUBUSWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    psubusw xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PHSUBWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    phsubw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PHSUBWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    phsubw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PHSUBWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    phsubw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PHSUBWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    phsubw xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PHSUBDr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    phsubd mm0, mm1
TEST_END_64

TEST_BEGIN_64(PHSUBDr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    phsubd mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PHSUBDv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    phsubd xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PHSUBDv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    phsubd xmm0, xmmword ptr [rsp]
TEST_END_64
