/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define CAT_3(a, b) a ## b
#define CAT_2(a, b) CAT_3(a, b)
#define CAT(a, b) CAT_2(a, b)

#define CAT3(a, b, c) CAT(a, CAT(b, c))

#define TO_STRING3(a) # a
#define TO_STRING2(a) TO_STRING3(a)
#define TO_STRING(a) TO_STRING2(a)

/* Note:    Apple mangles C symbol names to have a leading underscore. */
#ifdef __APPLE__
# define SYMBOL(x) CAT(_, x)
#else
# define SYMBOL(x) x
#endif

#define FUNC_NAME(instr_name, num_args) \
    CAT3(instr_name, _, num_args)

#ifdef IN_TEST_GENERATOR
# define TEST_PROLOGUE
#else
# define TEST_PROLOGUE \
    adrp    x28, SYMBOL(gNativeState) ; \
    add     x28, x28, :lo12:SYMBOL(gNativeState) ;
#endif  /* IN_TEST_GENERATOR */

/* Defines the beginning of a test function. The key detail is that tests
 * register themselves into data structures located in a special section of
 * the binary.
 *
 * Each test function is associated with a `struct TestInfo` (see Test.h). These
 * structures are placed into the `__aarch64_test_table` section of the binary,
 * and bracketed by the `__aarch64_test_table_begin` and
 * `__aarch64_test_table_end` symbols, respectively.
 */
#define TEST_BEGIN(isel_name, instr_name, num_args) \
    .text ; \
    \
    .align 16 ; \
    .globl SYMBOL(FUNC_NAME(instr_name, num_args)) ; \
    \
SYMBOL(FUNC_NAME(instr_name, num_args)): ; \
    .section "__aarch64_test_table", "a" ; \
    .balign 128 ; \
    1: \
    .quad 3f ; \
    .quad 7f ; \
    .quad 2f ; \
    .quad 4f ; \
    .quad 5f ; \
    .quad num_args ; \
    .quad 6f ; \
    \
    .rodata ; \
    2: \
    .asciz TO_STRING(FUNC_NAME(instr_name, num_args)) ; \
    6: \
    .asciz TO_STRING(isel_name) ; \
    \
    .text ; \
    3: \
    .cfi_startproc ; \
    TEST_PROLOGUE

/* Note:    The test end address is placed *before* the `RET` so that we can
 *          make sure that the end of a test marker is actually
 *          `__remill_detach`. This is kind of a hack.
 */
#ifdef IN_TEST_GENERATOR
# define TEST_END \
    7: \
    .cfi_endproc ; \
    .section "__aarch64_test_table", "a" ; \
    .quad 0 ; \
    hlt #0 ;

#else
# define TEST_END \
    7: \
    b SYMBOL(__aarch64_save_state_after) ; \
    .cfi_endproc ; \
    .section "__aarch64_test_table", "a" ; \
    .quad 0 ; \
    .text ; \
    hlt #0 ;
#endif  /* IN_TEST_GENERATOR */

/* Defines the possible inputs to provide test. We add an extra 3 null inputs
 * at the end so that we can purposely 'overflow' when accessing the array so
 * that we can always specify 3 inputs, even if the program uses fewer. */
#define TEST_INPUTS(...) \
    .data ; \
    .balign 8 ; \
    4: \
    .quad  __VA_ARGS__ ; \
    5: \
    .quad 0, 0, 0; \
    .text ;

#ifndef IN_TEST_GENERATOR
    .data
    .extern SYMBOL(gTestToRun)
    .extern SYMBOL(gLiftedState)
    .extern SYMBOL(gNativeState)
    .extern SYMBOL(gStackSwitcher)
    .extern SYMBOL(gTestEnd)
    .extern SYMBOL(gStackSaveSlots)
#endif  /* IN_TEST_GENERATOR */

    .align 16
SYMBOL(vec_data):
    .long 0x41414141, 0xabababab, 0xcdcdcdcd, 0xefefefef
    .long 0x29292929, 0x38383838, 0x47474747, 0x56565656
    .long 0x37373737, 0x82828282, 0x1a1a1a1a, 0x2b2b2b2b
    .long 0x96969696, 0x35353535, 0xaeaeaeae, 0xc4c4c4c4
    .long 0x3d3d3d3d, 0x21212121, 0x11223344, 0x55667788
    .long 0x00414243, 0x41004243, 0x41420043, 0x41424300
    .long 0x00abcdef, 0xab00cdef, 0xabcd00ef, 0xabcdef00
    .long 0x00001111, 0x22222222, 0x33333333, 0x44444444
    .long 0xaaaa0000, 0xbbbbbbbb, 0xcccccccc, 0xdddddddd
    .long 0x55555555, 0x00006666, 0x77777777, 0x77777777
    .long 0xabababab, 0xcdcd0000, 0xefefefef, 0x12121212

    .text

#ifndef IN_TEST_GENERATOR
    .align 16
    .globl SYMBOL(InvokeTestCase)
SYMBOL(InvokeTestCase):
    .cfi_startproc
    msr fpcr, xzr
    msr fpsr, xzr

    /* Fill in q0 through q7 with dummy values. */
    adrp    x28, SYMBOL(vec_data)
    add     x28, x28, :lo12:SYMBOL(vec_data)
    ldur    q0, [x28, #0]
    ldur    q1, [x28, #16]
    ldur    q2, [x28, #32]
    ldur    q3, [x28, #64]
    ldur    q4, [x28, #80]
    ldur    q5, [x28, #96]
    ldur    q6, [x28, #112]
    ldur    q7, [x28, #128]

    /* Get the address of stack save slots into x28 */
    adrp    x28, SYMBOL(gStackSaveSlots)
    add     x28, x28, :lo12:SYMBOL(gStackSaveSlots)

    str     x29, [x28, #8]  /* Save x29 into slot 1 */
    mov     x29, sp
    str     x29, [x28, #0]  /* Save the stack pointer into slot 0 */
    ldr     x29, [x28, #8]  /* Restore x29 */

    /* Swap off of the native stack */
    adrp    x28, SYMBOL(gStackSwitcher)
    add     x28, x28, :lo12:SYMBOL(gStackSwitcher)
    ldr     x28, [x28]
    mov     sp, x28

    /* Start by saving the current native state into the `gLiftedState`
     * structure. This will be used as the initial state when running the
     * lifted tests. */
    adrp    x28, SYMBOL(gLiftedState)
    add     x28, x28, :lo12:SYMBOL(gLiftedState)
#include "generated/Arch/AArch64/SaveState.S"

    /* Branch to the test to run */
    adrp    x28, SYMBOL(gTestToRun)
    add     x28, x28, :lo12:SYMBOL(gTestToRun)
    ldr     x28, [x28]
    msr fpcr, xzr
    msr fpsr, xzr
    br      x28

    .cfi_endproc

    .align 16
    .globl SYMBOL(__aarch64_save_state_after)
SYMBOL(__aarch64_save_state_after):
    .cfi_startproc
    /* Save the current native state into the `gNativeState`, which now
     * contains the post-test state for eventual comparison against lifted
     * execution. Finally, go and restore the originally saved state. */
    adrp    x28, SYMBOL(gNativeState)
    add     x28, x28, :lo12:SYMBOL(gNativeState)
#include "generated/Arch/AArch64/SaveState.S"
/*#include "generated/Arch/AArch64/RestoreState.S"*/

    adrp    x28, SYMBOL(gStackSaveSlots)
    add     x28, x28, :lo12:SYMBOL(gStackSaveSlots)
    ldr     x28, [x28]  /* Load the saves SP from slot 0 */
    mov     sp, x28

    ret
    .cfi_endproc
#endif  /* IN_TEST_GENERATOR */

     /* Create a symbol that represents the beginning of the test
      * information table. */
    .section "__aarch64_test_table", "a"
    .globl SYMBOL(__aarch64_test_table_begin)
SYMBOL(__aarch64_test_table_begin):

#define ARG1_64 x0
#define ARG1_32 w0

#define ARG2_64 x1
#define ARG2_32 w1

#define ARG3_64 x2
#define ARG3_32 w2

#define TEST_INPUTS_FP32    \
    0x3fffffff, 0x3fffffff,      \
    0x3fffffff, 0x40000000,      \
    0x40000000, 0x3fffffff,      \
    0x7FFFFFFF, 0x7FFFFFFF,      \
    0x80000000, 0x7FFFFFFF,      \
    0x7FFFFFFF, 0x80000000,      \
    0x80000000, 0x80000000

#define TEST_INPUTS_FP64    \
    0x3ff0000000000000 /* 1.000000 */, 0x3ff0000000000000, /* 1.000000 */    \
    0x3ff0000000000000 /* 1.000000 */, 0x4000000000000000, /* 2.000000 */    \
    0x4000000000000000 /* 2.000000 */, 0x3ff0000000000000, /* 1.000000 */    \
    0x3ff0000000000000 /* 1.000000 */, 0x7ff0000000000000, /* inf */         \
    0x7ff0000000000000 /* inf */, 0x3ff0000000000000, /* 1.000000 */         \
    0x3ff0000000000000 /* 1.000000 */, 0xfff0000000000000, /* -inf */        \
    0xfff0000000000000 /* -inf */, 0x3ff0000000000000, /* 1.000000 */        \
    0x7ff0000000000000 /* inf */, 0x7ff0000000000000, /* inf */              \
    0xfff0000000000000 /* -inf */, 0xfff0000000000000, /* -inf */            \
    0x3ff0000000000000 /* 1.000000 */, 0x7ff8000000000000, /* nan */         \
    0x7ff8000000000000 /* nan */, 0x3ff0000000000000, /* 1.000000 */         \
    0x7ff8000000000000 /* nan */, 0x7ff8000000000000, /* nan */              \
    0x7ff0000000000000 /* inf */, 0x7ff8000000000000, /* nan */              \
    0x7ff8000000000000 /* nan */, 0x7ff0000000000000 /* inf */


#if 1

#include "tests/AArch64/BINARY/ADD_n_ADDSUB_IMM.S"
#include "tests/AArch64/BINARY/ADD_n_ADDSUB_SHIFT.S"
#include "tests/AArch64/BINARY/ADD_32_ADDSUB_EXT.S"
#include "tests/AArch64/BINARY/ADD_64_ADDSUB_EXT.S"
#include "tests/AArch64/BINARY/ADDS_n_ADDSUB_EXT.S"
#include "tests/AArch64/BINARY/ADDS_n_ADDSUB_IMM.S"
#include "tests/AArch64/BINARY/ADDS_n_ADDSUB_SHIFT.S"
#include "tests/AArch64/BINARY/MADD_nA_DP_3SRC.S"
#include "tests/AArch64/BINARY/MSUB_nA_DP_3SRC.S"
#include "tests/AArch64/BINARY/SBC_n_ADDSUB_CARRY.S"
#include "tests/AArch64/BINARY/SBCS_n_ADDSUB_CARRY.S"
#include "tests/AArch64/BINARY/SDIV_n_DP_2SRC.S"
#include "tests/AArch64/BINARY/SMADDL_64WA_DP_3SRC.S"
#include "tests/AArch64/BINARY/SMULH_64_DP_3SRC.S"
#include "tests/AArch64/BINARY/SUB_n_ADDSUB_IMM.S"
#include "tests/AArch64/BINARY/SUB_n_ADDSUB_SHIFT.S"
#include "tests/AArch64/BINARY/SUB_32_ADDSUB_EXT.S"
#include "tests/AArch64/BINARY/SUB_64_ADDSUB_EXT.S"
#include "tests/AArch64/BINARY/SUBS_n_ADDSUB_EXT.S"
#include "tests/AArch64/BINARY/SUBS_n_ADDSUB_IMM.S"
#include "tests/AArch64/BINARY/SUBS_n_ADDSUB_SHIFT.S"
#include "tests/AArch64/BINARY/UDIV_n_DP_2SRC.S"
#include "tests/AArch64/BINARY/UMADDL_64WA_DP_3SRC.S"
#include "tests/AArch64/BINARY/UMULH_64_DP_3SRC.S"
#include "tests/AArch64/BINARY/FADD_t_FLOATDP2.S"
#include "tests/AArch64/BINARY/FSUB_t_FLOATDP2.S"
#include "tests/AArch64/BINARY/FMUL_t_FLOATDP2.S"
#include "tests/AArch64/BINARY/FDIV_t_FLOATDP2.S"
#include "tests/AArch64/BINARY/FCMPx_n_FLOATCMP.S"
#include "tests/AArch64/BINARY/FABS_t_FLOATDP1.S"
#include "tests/AArch64/BINARY/FNEG_t_FLOATDP1.S"
#include "tests/AArch64/BINARY/FMADD_t_FLOATDP3.S"

#include "tests/AArch64/BITBYTE/BFM_nM_BITFIELD.S"
#include "tests/AArch64/BITBYTE/CLZ_n_DP_1SRC.S"
#include "tests/AArch64/BITBYTE/EXTR_n_EXTRACT.S"
#include "tests/AArch64/BITBYTE/RBIT.S"
#include "tests/AArch64/BITBYTE/REV.S"
#include "tests/AArch64/BITBYTE/SBFM_nM_BITFIELD.S"
#include "tests/AArch64/BITBYTE/UBFM_nM_BITFIELD.S"

#include "tests/AArch64/BRANCH/B_ONLY_CONDBRANCH.S"
#include "tests/AArch64/BRANCH/CBNZ_n_COMPBRANCH.S"
#include "tests/AArch64/BRANCH/CBZ_n_COMPBRANCH.S"
#include "tests/AArch64/BRANCH/TBNZ_ONLY_TESTBRANCH.S"
#include "tests/AArch64/BRANCH/TBZ_ONLY_TESTBRANCH.S"

#include "tests/AArch64/CONVERT/FCVTZx_nS_FLOAT2INT.S"
#include "tests/AArch64/CONVERT/FCVT_t_FLOAT2INT.S"
#include "tests/AArch64/CONVERT/SCVTF_n_FLOAT2INT.S"
#include "tests/AArch64/CONVERT/UCVTF_n_FLOAT2INT.S"

#include "tests/AArch64/DATAXFER/FMOV_t_FLOATIMM.S"
#include "tests/AArch64/DATAXFER/FMOV_NToN.S"
#include "tests/AArch64/DATAXFER/ST1_ASISDLSE_R1_1V.S"
#include "tests/AArch64/DATAXFER/ST1_ASISDLSE_R2_2V.S"
#include "tests/AArch64/DATAXFER/ST1_ASISDLSEP_I2_I2.S"
#include "tests/AArch64/DATAXFER/LD1_ASISDLSE_R1_1V.S"
#include "tests/AArch64/DATAXFER/LD1_ASISDLSE_R2_2V.S"
#include "tests/AArch64/DATAXFER/LD1_ASISDLSE_R3_3V.S"
#include "tests/AArch64/DATAXFER/LD1_ASISDLSE_R4_4V.S"
#include "tests/AArch64/DATAXFER/LD1_ASISDLSEP_I1_I1.S"
#include "tests/AArch64/DATAXFER/LD1_ASISDLSEP_I2_I2.S"
#include "tests/AArch64/DATAXFER/LD1_ASISDLSEP_I3_I3.S"
#include "tests/AArch64/DATAXFER/LD1_ASISDLSEP_I4_I4.S"
#include "tests/AArch64/DATAXFER/LD2_ASISDLSE_R2.S"
#include "tests/AArch64/DATAXFER/LD2_ASISDLSEP_R2_R.S"
#include "tests/AArch64/DATAXFER/LD2_ASISDLSEP_I2_I.S"
#include "tests/AArch64/DATAXFER/LD3_ASISDLSE_R3.S"
#include "tests/AArch64/DATAXFER/LD4_ASISDLSE_R4.S"
#include "tests/AArch64/DATAXFER/LDPSW_64_LDSTPAIR.S"
#include "tests/AArch64/DATAXFER/LDP_n_LDSTPAIR_OFF.S"
#include "tests/AArch64/DATAXFER/LDP_n_LDSTPAIR_POST.S"
#include "tests/AArch64/DATAXFER/LDP_n_LDSTPAIR_PRE.S"
#include "tests/AArch64/DATAXFER/LDR_n_LDST_IMMPOST.S"
#include "tests/AArch64/DATAXFER/LDR_n_LDST_IMMPRE.S"
#include "tests/AArch64/DATAXFER/LDR_n_LDST_POS.S"
#include "tests/AArch64/DATAXFER/LDR_n_LDST_REGOFF.S"
#include "tests/AArch64/DATAXFER/LDRB.S"
#include "tests/AArch64/DATAXFER/LDRH.S"
#include "tests/AArch64/DATAXFER/LDRSB.S"
#include "tests/AArch64/DATAXFER/LDRSH.S"
#include "tests/AArch64/DATAXFER/LDRSW.S"
#include "tests/AArch64/DATAXFER/LDUR_n_LDST_UNSCALED.S"
#include "tests/AArch64/DATAXFER/LDURS_n_LDST_UNSCALED.S"
#include "tests/AArch64/DATAXFER/LDXR_LRn_LDSTEXCL.S"
#include "tests/AArch64/DATAXFER/MOVI_ASIMDIMM.S"
#include "tests/AArch64/DATAXFER/MOVK_n_MOVEWIDE.S"
#include "tests/AArch64/DATAXFER/MOVZ_n_MOVEWIDE.S"
#include "tests/AArch64/DATAXFER/MVNI_ASIMDIMM.S"
#include "tests/AArch64/DATAXFER/SMOV.S"
#include "tests/AArch64/DATAXFER/STLXR_SRn_LDSTEXCL.S"
#include "tests/AArch64/DATAXFER/STP_n_LDSTPAIR_OFF.S"
#include "tests/AArch64/DATAXFER/STP_n_LDSTPAIR_POST.S"
#include "tests/AArch64/DATAXFER/STP_n_LDSTPAIR_PRE.S"
#include "tests/AArch64/DATAXFER/STR_n_LDST_POS.S"
#include "tests/AArch64/DATAXFER/STR_n_LDST_IMMPRE.S"
#include "tests/AArch64/DATAXFER/STR_n_LDST_IMMPOST.S"
#include "tests/AArch64/DATAXFER/STR_n_LDST_REGOFF.S"
#include "tests/AArch64/DATAXFER/STRB.S"
#include "tests/AArch64/DATAXFER/STRH.S"
#include "tests/AArch64/DATAXFER/STLR.S"
#include "tests/AArch64/DATAXFER/STUR_n_LDST_UNSCALED.S"
#include "tests/AArch64/DATAXFER/UMOV.S"
#include "tests/AArch64/DATAXFER/INS_ASIMDINS_IR_R.S"

#include "tests/AArch64/LOGICAL/AND_n_LOG_IMM.S"
#include "tests/AArch64/LOGICAL/AND_n_LOG_SHIFT.S"
#include "tests/AArch64/LOGICAL/ANDS_nS_LOG_IMM.S"
#include "tests/AArch64/LOGICAL/ANDS_n_LOG_SHIFT.S"
#include "tests/AArch64/LOGICAL/BIC_n_LOG_SHIFT.S"
#include "tests/AArch64/LOGICAL/BICS_n_LOG_SHIFT.S"
#include "tests/AArch64/LOGICAL/EOR_n_LOG_IMM.S"
#include "tests/AArch64/LOGICAL/EOR_n_LOG_SHIFT.S"
#include "tests/AArch64/LOGICAL/EON_n_LOG_SHIFT.S"
#include "tests/AArch64/LOGICAL/ORN_n_LOG_SHIFT.S"
#include "tests/AArch64/LOGICAL/ORR_n_LOG_IMM.S"
#include "tests/AArch64/LOGICAL/ORR_n_LOG_SHIFT.S"

#include "tests/AArch64/MISC/NOP.S"

#include "tests/AArch64/COND/CSEL_n_CONDSEL.S"
#include "tests/AArch64/COND/x_CSNEG_n_CONDSEL.S"
#include "tests/AArch64/COND/CCMP_n_CONDCMP_IMM.S"
#include "tests/AArch64/COND/x_CSINC_n_CONDSEL.S"
#include "tests/AArch64/COND/x_CSINV_n_CONDSEL.S"
#include "tests/AArch64/COND/CCMN_n_CONDCMP_IMM.S"

#include "tests/AArch64/SIMD/ADD_ASIMDSAME_ONLY.S"
#include "tests/AArch64/SIMD/ADDP_ASIMDSAME_ONLY.S"
#include "tests/AArch64/SIMD/ADDV_ASIMDALL_ONLY.S"
#include "tests/AArch64/SIMD/BIC_ASIMDSAME_ONLY.S"
#include "tests/AArch64/SIMD/BIF_ASIMDSAME_ONLY.S"
#include "tests/AArch64/SIMD/BIT_ASIMDSAME_ONLY.S"
#include "tests/AArch64/SIMD/BSL_ASIMDSAME_ONLY.S"
#include "tests/AArch64/SIMD/CMcc_ASIMDMISC_Z.S"
#include "tests/AArch64/SIMD/CMcc_ASIMDSAME_ONLY.S"
#include "tests/AArch64/SIMD/DUP_ASIMDINS_DR_R.S"
#include "tests/AArch64/SIMD/EOR_ASIMDSAME_ONLY.S"
#include "tests/AArch64/SIMD/FMAXV_ASIMDALL_ONLY_SD_4S.S"
#include "tests/AArch64/SIMD/FMINV_ASIMDALL_ONLY_SD_4S.S"
#include "tests/AArch64/SIMD/ORR_ASIMDSAME_ONLY.S"
#include "tests/AArch64/SIMD/FMOV_VECTORS.S"
#include "tests/AArch64/SIMD/SMAX_ASIMDSAME_ONLY.S"
#include "tests/AArch64/SIMD/SMAXP_ASIMDSAME_ONLY.S"
#include "tests/AArch64/SIMD/SMAXV_ASIMDALL_ONLY.S"
#include "tests/AArch64/SIMD/SMIN_ASIMDSAME_ONLY.S"
#include "tests/AArch64/SIMD/SMINP_ASIMDSAME_ONLY.S"
#include "tests/AArch64/SIMD/SMINV_ASIMDALL_ONLY.S"
#include "tests/AArch64/SIMD/SUB_ASIMDSAME_ONLY.S"
#include "tests/AArch64/SIMD/UMAX_ASIMDSAME_ONLY.S"
#include "tests/AArch64/SIMD/UMAXP_ASIMDSAME_ONLY.S"
#include "tests/AArch64/SIMD/UMAXV_ASIMDALL_ONLY.S"
#include "tests/AArch64/SIMD/UMIN_ASIMDSAME_ONLY.S"
#include "tests/AArch64/SIMD/UMINP_ASIMDSAME_ONLY.S"
#include "tests/AArch64/SIMD/UMINV_ASIMDALL_ONLY.S"
#include "tests/AArch64/SIMD/NOT_ASIMDMISC_R.S"
#include "tests/AArch64/SIMD/EXT_ASIMDINS_ONLY.S"
#include "tests/AArch64/SIMD/USHR_ASISDSHF_R.S"


#include "tests/AArch64/SYSTEM/Mn_n_SYSTEM_FPSR.S"
#include "tests/AArch64/SYSTEM/Mn_n_SYSTEM_FPCR.S"
#include "tests/AArch64/SYSTEM/Mn_n_SYSTEM_TPIDR_EL0.S"

#endif

     /* Create a symbol that represents the end of the test information table. */
    .section "__aarch64_test_table", "a"
    .globl SYMBOL(__aarch64_test_table_end)
SYMBOL(__aarch64_test_table_end):

