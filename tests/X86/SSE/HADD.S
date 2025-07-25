#define INPUT_HADD \
    0x3fa0000000000000 /* 1.000000 */, 0x3ff0000000000000, /* 1.000000 */   \
    0x3ff0000000000000 /* 1.000000 */, 0x4000000000000000, /* 2.000000 */   \
    0x4000000000000000 /* 2.000000 */, 0x3ff0000000000000, /* 1.000000 */   \
    0x3ff0000000000000 /* 1.000000 */, 0x7ff0000000000000, /* inf */        \
    0x7ff0000000000000 /* inf */, 0x3ff0000000000000, /* 1.000000 */        \
    0x3ff0000000000000 /* 1.000000 */, 0xfff0000000000000, /* -inf */       \
    0xfff0000000000000 /* -inf */, 0x3ff0000000000000, /* 1.000000 */       \
    0x7ff0000000000000 /* inf */, 0x7ff0000000000000, /* inf */             \
    0xfff0000000000000 /* -inf */, 0xfff0000000000000, /* -inf */           \
    0x3ff0000000000000 /* 1.000000 */, 0x7ff8000000000000, /* nan */        \
    0x7ff8000000000000 /* nan */, 0x3ff0000000000000, /* 1.000000 */        \
    0x7ff8000000000000 /* nan */, 0x7ff8000000000000, /* nan */             \
    0x7ff0000000000000 /* inf */, 0x7ff8000000000000, /* nan */             \
    0x7ff8000000000000 /* nan */, 0x7ff0000000000000 /* inf */              \

TEST_BEGIN_64(HADDPSv128v128, 2)
TEST_INPUTS(INPUT_HADD)
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    haddps xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(HADDPSv128m128, 2)
TEST_INPUTS(INPUT_HADD)
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    haddps xmm0, xmmword ptr [rsp]
TEST_END_64

#if HAS_FEATURE_AVX  

TEST_BEGIN_64(VHADDPSv128v128v128, 2)
TEST_INPUTS(INPUT_HADD)
    movq xmm1, ARG1_64
    movq xmm2, ARG2_64
    vhaddps xmm0, xmm1, xmm2
TEST_END_64

TEST_BEGIN_64(VHADDPSv128v128m128, 2)
TEST_INPUTS(INPUT_HADD)
    movq xmm1, ARG1_64   
    push 0
    push ARG2_64
    vhaddps xmm0, xmm1, [rsp]
TEST_END_64

TEST_BEGIN_64(VHADDPSv256v256v256, 2)
TEST_INPUTS(0)
    vhaddps ymm0, ymm1, ymm2;
TEST_END_64

TEST_BEGIN_64(VHADDPSv256v256m256, 2)
TEST_INPUTS(0)
    vmovdqu [rsp - 32], ymm0;
    vhaddps ymm0, ymm1, ymmword ptr [rsp - 32];
TEST_END_64

#endif  // HAS_FEATURE_AVX


TEST_BEGIN_64(HADDPDv128v128, 2)
TEST_INPUTS(INPUT_HADD)
    movq xmm0, ARG1_64
    movq xmm1, ARG2_64
    haddpd xmm0, xmm1
TEST_END_64

TEST_BEGIN_64(HADDPDv128m128, 2)
TEST_INPUTS(INPUT_HADD)
    push 0
    push ARG2_64
    movq xmm0, ARG1_64
    haddpd xmm0, xmmword ptr [rsp]
TEST_END_64

#if HAS_FEATURE_AVX  

TEST_BEGIN_64(VHADDPDv128v128v128, 2)
TEST_INPUTS(INPUT_HADD)
    movq xmm1, ARG1_64
    movq xmm2, ARG2_64
    vhaddpd xmm0, xmm1, xmm2
TEST_END_64

TEST_BEGIN_64(VHADDPDv128v128m128, 2)
TEST_INPUTS(INPUT_HADD)
    movq xmm1, ARG1_64   
    push 0
    push ARG2_64
    vhaddpd xmm0, xmm1, [rsp]
TEST_END_64

TEST_BEGIN_64(VHADDPDv256v256v256, 2)
TEST_INPUTS(0)
    vhaddpd ymm0, ymm1, ymm2;
TEST_END_64

TEST_BEGIN_64(VHADDPDv256v256m256, 2)
TEST_INPUTS(0)
    vmovdqu [rsp - 32], ymm0;
    vhaddpd ymm0, ymm1, ymmword ptr [rsp - 32];
TEST_END_64

#endif  // HAS_FEATURE_AVX