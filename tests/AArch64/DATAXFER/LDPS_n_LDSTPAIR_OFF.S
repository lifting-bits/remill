
/* LDP  <Xt1>, <Xt2>, [<Xn|SP>{, #<imm>}] */
TEST_BEGIN(LDPSW_64_LDSTPAIR_OFF, ldpsw_x0_x1_m64_off, 1)
TEST_INPUTS(0x00FFFFFFFFFFFFFF)
    add x3, sp, #-256
    str ARG1_64, [x3, #0]
    ldpsw x4, x5, [x3, #0]
    ldpsw x6, x7, [x3, #32]
    ldpsw x8, x9, [x3, #64]
TEST_END

