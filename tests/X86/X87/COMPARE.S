/* SPDX-License-Identifier: Apache-2.0 */

X87_INPUT cmp_less, 0x8000000000000000, 0x3fff, 0x8000000000000000, 0x4000
X87_INPUT cmp_greater, 0x8000000000000000, 0x4000
X87_INPUT cmp_equal, 0x8000000000000000, 0x3fff
X87_INPUT cmp_negative, 0x8000000000000000, 0xbfff
X87_INPUT cmp_zeros, 0, 0x8000, 0, 0
X87_INPUT cmp_inf, 0x8000000000000000, 0x7fff
X87_INPUT cmp_ninf, 0x8000000000000000, 0xffff
X87_INPUT cmp_inf_equal, 0x8000000000000000, 0x7fff, 0x8000000000000000, 0x7fff
X87_INPUT cmp_qnan_left, 0xc000000000000123, 0x7fff
X87_INPUT cmp_qnan_right, 0x8000000000000000, 0x3fff, 0xc000000000000123, 0x7fff
X87_INPUT cmp_snan_left, 0x8000000000000123, 0x7fff
X87_INPUT cmp_snan_right, 0x8000000000000000, 0x3fff, 0x8000000000000123, 0x7fff
X87_INPUT cmp_qnan_snan, 0xc000000000000123, 0x7fff, 0x8000000000000123, 0x7fff
X87_INPUT cmp_snan_qnan, 0x8000000000000123, 0x7fff, 0xc000000000000123, 0x7fff
X87_INPUT cmp_two_snans, 0x8000000000000123, 0x7fff, 0x8000000000000123, 0x7fff
X87_INPUT cmp_two_qnans, 0xc000000000000123, 0x7fff, 0xc000000000000123, 0x7fff
X87_INPUT cmp_denormal_left, 1, 0
X87_INPUT cmp_denormal_right, 0x8000000000000000, 0x3fff, 1, 0

/* C1 is excluded: native Intel/AMD behavior and the SDM disagree. */
#define COMPARE_CASE(name, opcode1, opcode2) \
    TEST_BEGIN_FPU(name, 3, 0x7d7f, TEST_FPU_INPUTS | TEST_FPU_RAW_REGISTERS | TEST_TWO_FLAGS) \
    .data ; .balign 8 ; 4: ; \
    .irp value, cmp_less,cmp_greater,cmp_equal,cmp_negative,cmp_zeros,cmp_inf,cmp_ninf,cmp_inf_equal,cmp_qnan_left,cmp_qnan_right,cmp_snan_left,cmp_snan_right,cmp_qnan_snan,cmp_snan_qnan,cmp_two_snans,cmp_two_qnans,cmp_denormal_left,cmp_denormal_right ; \
    .irp prior, 0,1,2,63 ; \
    .irp top, 0,1,2,3,4,5,6,7 ; \
        .quad \value, 0x37f | ((0x4300 | \prior | (\top << 11)) << 16), 0x1f80 ; \
    .endr ; .endr ; .endr ; \
    5: ; .quad 0,0,0 ; .text ; \
    .byte opcode1, opcode2 ; \
    TEST_END

COMPARE_CASE(FCOM_STICKY, 0xd8, 0xd1)
COMPARE_CASE(FCOMP_STICKY, 0xd8, 0xd9)
COMPARE_CASE(FCOMPP_STICKY, 0xde, 0xd9)
COMPARE_CASE(FCOMI_STICKY, 0xdb, 0xf1)
COMPARE_CASE(FCOMIP_STICKY, 0xdf, 0xf1)
COMPARE_CASE(FUCOM_STICKY, 0xdd, 0xe1)
COMPARE_CASE(FUCOMP_STICKY, 0xdd, 0xe9)
COMPARE_CASE(FUCOMPP_STICKY, 0xda, 0xe9)
COMPARE_CASE(FUCOMI_STICKY, 0xdb, 0xe9)
COMPARE_CASE(FUCOMIP_STICKY, 0xdf, 0xe9)

#undef COMPARE_CASE
