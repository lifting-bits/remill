/* SPDX-License-Identifier: Apache-2.0 */

#if defined(IN_TEST_GENERATOR) && ADDRESS_SIZE_BITS == 32
    .code32
#endif

TEST_BEGIN_FPU(FLDCW_RESERVED, 1, 0, TEST_SINGLE_FLAGS)
    .data
    .balign 8
4:
    .set cw, 0
    .rept 65536
        .quad cw
        .set cw, cw + 1
    .endr
5:
    .quad 0,0,0
    .text
    lea SP_ADDR, [SP_ADDR - 16]
    mov WORD PTR [SP_ADDR], ARG1_16
    fldcw WORD PTR [SP_ADDR]
    fnstcw WORD PTR [SP_ADDR + 2]
TEST_END

X87_INPUT control_input, 0, 0

TEST_BEGIN_FPU(FPU_CONTROL_READBACK, 3, 0x7d7f, TEST_FPU_INPUTS | TEST_FPU_MXCSR | TEST_SINGLE_FLAGS | TEST_HOST_FLAGS)
    .data
    .balign 8
4:
    .irp pc, 0,2,3
    .irp rc, 0,1,2,3
    .irp host, 0,1,2,3
    .irp extra, 0,0x807f
        .quad control_input, 0x7f | (\pc << 8) | (\rc << 10)
        .quad 0x1f80 | (((\rc + 1) & 3) << 13) | \extra | (\host << 32)
    .endr
    .endr
    .endr
    .endr
5:
    .quad 0,0,0
    .text
    lea SP_ADDR, [SP_ADDR - 16]
    fnstcw WORD PTR [SP_ADDR]
    stmxcsr DWORD PTR [SP_ADDR + 4]
TEST_END

X87_INPUT arithmetic_input, 0x8000000000000000, 0x3fff, 0x8000000000000000, 0x3fbf

TEST_BEGIN_FPU(FPU_INDEPENDENT_ROUNDING, 3, 0x383f, TEST_FPU_INPUTS | TEST_FPU_RAW_REGISTERS | TEST_SINGLE_FLAGS)
    .data
    .balign 8
4:
    .irp rc, 0,1,2,3
    .irp simd, 0,1,2,3
    .irp host, 0,1,2,3
        .quad arithmetic_input, 0x37f | (\rc << 10)
        .quad 0x1f80 | (\simd << 13) | (\host << 32)
    .endr
    .endr
    .endr
5:
    .quad 0,0,0
    .text
    lea SP_ADDR, [SP_ADDR - 32]
    mov DWORD PTR [SP_ADDR], 0
    mov DWORD PTR [SP_ADDR + 4], 0x3ff00000
    mov DWORD PTR [SP_ADDR + 8], 0
    mov DWORD PTR [SP_ADDR + 12], 0x3ca00000
    mov DWORD PTR [SP_ADDR + 16], 0
    mov DWORD PTR [SP_ADDR + 20], 0x40040000
    movsd xmm0, QWORD PTR [SP_ADDR]
    movsd xmm1, QWORD PTR [SP_ADDR + 8]
    fadd st(0), st(1)
    addsd xmm0, xmm1
    cvtsd2si eax, QWORD PTR [SP_ADDR + 16]
TEST_END

#if defined(IN_TEST_GENERATOR) && ADDRESS_SIZE_BITS == 32
    .code64
#endif
