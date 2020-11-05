/* VINSERTF128.S */
#if HAS_FEATURE_AVX

TEST_BEGIN(VINSERTF128, 3)
TEST_INPUTS(
    0x7ff8000012345678,0x0123456789abcdef,0xfedcba9876543210,
    0x7ff8000012345678,0x1111222233334444,0x5555666677778888
)
    push 0;
    push ARG2_64;
    push 0;
    push ARG3_64;
    vmovdqu ymm2, [rsp];
    movq xmm3, ARG1_64;
    vinsertf128 ymm1, ymm2, xmm3, 1;
TEST_END

#endif  // HAS_FEATURE_AVX
