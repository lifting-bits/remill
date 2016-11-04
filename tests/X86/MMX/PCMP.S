
TEST_BEGIN_64(PCMPEQBr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pcmpeqb mm0, mm1
TEST_END_64

TEST_BEGIN_64(PCMPEQBr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pcmpeqb mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PCMPEQBv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pcmpeqb xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PCMPEQBv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pcmpeqb xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PCMPEQWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pcmpeqw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PCMPEQWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pcmpeqw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PCMPEQWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pcmpeqw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PCMPEQWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pcmpeqw xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PCMPEQDr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pcmpeqd mm0, mm1
TEST_END_64

TEST_BEGIN_64(PCMPEQDr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pcmpeqd mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PCMPEQDv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pcmpeqd xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PCMPEQDv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pcmpeqd xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PCMPGTBr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pcmpgtb mm0, mm1
TEST_END_64

TEST_BEGIN_64(PCMPGTBr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pcmpgtb mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PCMPGTBv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pcmpgtb xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PCMPGTBv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pcmpgtb xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PCMPGTWr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pcmpgtw mm0, mm1
TEST_END_64

TEST_BEGIN_64(PCMPGTWr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pcmpgtw mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PCMPGTWv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pcmpgtw xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PCMPGTWv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pcmpgtw xmm0, xmmword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PCMPGTDr64r64, 2)
TEST_INPUTS_MMX_2()
    movq mm0, ARG1_64
    movq mm1, ARG2_64
    pcmpgtd mm0, mm1
TEST_END_64

TEST_BEGIN_64(PCMPGTDr64m64, 2)
TEST_INPUTS_MMX_2()
    push ARG2_64
    movq mm0, ARG1_64
    pcmpgtd mm0, qword ptr [rsp]
TEST_END_64

TEST_BEGIN_64(PCMPGTDv128v128, 2)
TEST_INPUTS_MMX_2()
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    pcmpgtd xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(PCMPGTDv128m128, 2)
TEST_INPUTS_MMX_2()
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    pcmpgtd xmm0, xmmword ptr [rsp]
TEST_END_64
