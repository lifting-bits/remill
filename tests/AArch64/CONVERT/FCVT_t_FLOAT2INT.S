TEST_BEGIN(FCVT_SD_FLOATDP1, fcvt_s0_d0, 1)
TEST_INPUTS(
    // 0x00000000, 
    // 0x3fffffff,
    // 0x40000000,     
    // 0x7FFFFFFF, 
    // 0x80000000,      
    // 0xffffffff,
    // 0xbf800000,
    0xc0000000,
    0xcccccccccccccccc)
    // 0xbf8ccccccccccccc,
    // 0xffffffffffffffff)

    fmov d0, ARG1_64
    fcvt s1, d0
TEST_END
