/* SPDX-License-Identifier: Apache-2.0 */

#if defined(IN_TEST_GENERATOR) && ADDRESS_SIZE_BITS == 32
    .code32
#endif

X87_INPUT round_2_5, 0xa000000000000000, 0x4000
X87_INPUT round_3_5, 0xe000000000000000, 0x4000
X87_INPUT round_n2_5, 0xa000000000000000, 0xc000
X87_INPUT round_n3_5, 0xe000000000000000, 0xc000
X87_INPUT round_nquarter, 0x8000000000000000, 0xbffd
X87_INPUT round_nzero, 0, 0x8000
X87_INPUT round_large, 0x800000a000000000, 0x4017
X87_INPUT round_i16_edge, 0xffff000000000000, 0x400d
X87_INPUT round_i32_edge, 0x8000000000000000, 0x401e
X87_INPUT round_i64_edge, 0x8000000000000000, 0x403e
X87_INPUT round_infinity, 0x8000000000000000, 0x7fff
X87_INPUT round_qnan, 0xc000000000000123, 0x7fff
X87_INPUT round_bcd_edge, 0xde0b6b3a76400000, 0x403a

#define ROUND_INPUTS \
    .data ; .balign 8 ; 4: ; \
    .irp value, round_2_5,round_3_5,round_n2_5,round_n3_5,round_nquarter,round_nzero,round_large,round_i16_edge,round_i32_edge,round_i64_edge,round_infinity,round_qnan,round_bcd_edge ; \
    .irp pc, 0,2,3 ; \
    .irp rc, 0,1,2,3 ; \
    .irp host, 0,1,2,3 ; \
    .irp prior, 0,0x21 ; \
        .quad \value, 0x7f | (\pc << 8) | (\rc << 10) | (\prior << 16) ; \
        .quad 0x1f80 | (((\rc + 1) & 3) << 13) | (\host << 32) ; \
    .endr ; .endr ; .endr ; .endr ; .endr ; \
    5: ; .quad 0,0,0 ; .text ;

#define ROUND_CASE(name, ...) \
    TEST_BEGIN_FPU(name, 3, 0x3a3f, TEST_FPU_INPUTS | TEST_FPU_RAW_REGISTERS | TEST_SINGLE_FLAGS) \
    ROUND_INPUTS \
    lea SP_ADDR, [SP_ADDR - 16] ; \
    __VA_ARGS__ ; \
    TEST_END

ROUND_CASE(FRNDINT_RC, frndint)
ROUND_CASE(FIST16_RC, fist WORD PTR [SP_ADDR])
ROUND_CASE(FIST32_RC, fist DWORD PTR [SP_ADDR])
ROUND_CASE(FISTP16_RC, fistp WORD PTR [SP_ADDR])
ROUND_CASE(FISTP32_RC, fistp DWORD PTR [SP_ADDR])
ROUND_CASE(FISTP64_RC, fistp QWORD PTR [SP_ADDR])
ROUND_CASE(FISTTP64_RC, fisttp QWORD PTR [SP_ADDR])
ROUND_CASE(FBSTP_RC, fbstp TBYTE PTR [SP_ADDR])

#undef ROUND_CASE
#undef ROUND_INPUTS

#if defined(IN_TEST_GENERATOR) && ADDRESS_SIZE_BITS == 32
    .code64
#endif
