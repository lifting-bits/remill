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

#include "remill/Arch/Assembly.S"

#ifndef ADDRESS_SIZE_BITS
# define ADDRESS_SIZE_BITS 64
#endif

#ifndef HAS_FEATURE_AVX
# define HAS_FEATURE_AVX 1
#endif

#ifndef HAS_FEATURE_AVX512
# define HAS_FEATURE_AVX512 1
#endif


#ifdef __APPLE__
# define IF_NOT_APPLE_(...)
#else
# define IF_NOT_APPLE_(...) __VA_ARGS__ ,
#endif
        
#define FUNC_NAME(instr_name, num_args) \
    CAT3(instr_name, _, num_args)
        
/* Defines the beginning of a test function. The key detail is that tests
 * register themselves into data structures located in a special section of
 * the binary.
 *
 * Each test function is associated with a `struct TestInfo` (see Test.h). These
 * structures are placed into the `__x86_test_table` section of the binary, and
 * bracketed by the `__x86_test_table_begin` and `__x86_test_table_end`
 * symbols, respectively.
 *
 * Note: These test cases must be usable in 32- and 64-bit modes. Otherwise
 *       one should use `TEST_BEGIN_32` or `TEST_BEGIN_64`.
 */
#define TEST_BEGIN(instr_name, num_args) \
    TEXT_SECTION ; \
    \
    .align 16 ; \
    .globl SYMBOL(FUNC_NAME(instr_name, num_args)) ; \
    \
SYMBOL(FUNC_NAME(instr_name, num_args)): ; \
    \
    .section "__x86_test_table", "a" ; \
    .balign 128 ; \
    1: \
    .quad 3f ; \
    .quad 6f ; \
    .quad 2f ; \
    .quad 4f ; \
    .quad 5f ; \
    .quad num_args ; \
    \
    CONST_SECTION ; \
    2: \
    .asciz TO_STRING(FUNC_NAME(instr_name, num_args)) ; \
    \
    TEXT_SECTION ; \
    3: \
    .cfi_startproc ;

/* Note:    The test end address is placed *before* the `RET` so that we can
 *          make sure that the end of a test marker is actually
 *          `__remill_detach`. This is kind of a hack.
 */
#ifdef IN_TEST_GENERATOR
# define TEST_END \
    6: \
    .cfi_endproc ; \
    .section "__x86_test_table", "a" ; \
    .quad 0 ; \
    .text ; \
    ud2 ;

#else
# define TEST_END \
    6: \
    jmp SYMBOL(__x86_save_state_after) ; \
    .cfi_endproc ; \
    .section "__x86_test_table", "a" ; \
    .quad 0 ; \
    .text ; \
    ud2 ;
#endif

#define CF | (1 << 0)
#define PF | (1 << 2)
#define AF | (1 << 4)
#define ZF | (1 << 6)
#define SF | (1 << 7)
#define DF | (1 << 10)
#define OF | (1 << 11)

#define TEST_IGNORE_FLAGS(...) \
    .section "__x86_test_table", "a" ; \
    .quad 0 __VA_ARGS__ ; \
    .text ;

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

/* Specify the beginning and end of a 32- and 64-bit-specific tests. */
#if 64 == ADDRESS_SIZE_BITS
# define TEST_BEGIN_64 TEST_BEGIN
# define TEST_END_64 TEST_END

#else
# define TEST_BEGIN_64(instr_name, num_args) \
      .macro IGNORE_ ## instr_name ## __LINE__
# define TEST_END_64 \
      .endm ;

#endif  /* 64 == ADDRESS_SIZE_BITS */

#ifdef __APPLE__
# define TEST_BEGIN_MEM_64(instr_name, num_args) \
      .macro IGNORE_ ## instr_name ## __LINE__
# define TEST_END_MEM_64 \
      .endm ;
# define TEST_BEGIN_MEM(instr_name, num_args) \
      .macro IGNORE_ ## instr_name ## __LINE__
# define TEST_END_MEM \
      .endm ;
#else
# define TEST_BEGIN_MEM TEST_BEGIN
# define TEST_END_MEM TEST_END
# define TEST_BEGIN_MEM_64 TEST_BEGIN_64
# define TEST_END_MEM_64 TEST_END_64
#endif

    .intel_syntax noprefix ;

#ifndef IN_TEST_GENERATOR
    DATA_SECTION
    .extern SYMBOL(gTestToRun)
    .extern SYMBOL(gLiftedState)
    .extern SYMBOL(gNativeState)
    .extern SYMBOL(gStackSwitcher)
    .extern SYMBOL(gTestEnd)
    .extern SYMBOL(gStackSaveSlot)
    .extern SYMBOL(gRflagsForTest)

    CONST_SECTION
    .align 16
SYMBOL(fpu_cwd):
    .long 0x37F  /* Default is 0x37F */

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

// Set all bits in a vector.
#if HAS_FEATURE_AVX
# define SET_VEC(num) vmovdqu ymm ## num , [RIP + SYMBOL(vec_data) + (num*16)]
#else
# define SET_VEC(num) movdqu xmm ## num , [RIP + SYMBOL(vec_data) + (num*16)]
#endif

    /* This function tail-calls to the test that we want to run via the
     * `gTestToRun` pointer.
     */
    TEXT_SECTION
    .extern SYMBOL(__remill_detach)
    .align 16
    .globl SYMBOL(DoInvokeTestCase)
SYMBOL(DoInvokeTestCase):
    .cfi_startproc

    /* Reset the FPU, and fill the stack with +0.0.
     *
     * Note:    The FPU reset defaults to overflow/underflow exceptions being
     *          masked so we can "safely" push/pop beyond what we should be able
     *          to reasonably do.
     *
     * Note:    The second `fninit` is because the first one won't overwrite
     *          the data stored in the ST(n) regs. So, we reset to deal with
     *          overflow, then clear out the entries, then reset again to deal
     *          with the tag word. Resetting the tag word lets us distinguish
     *          (not very well) between MMX- and X87-using tests.
     */
    fninit
    fldz
    fldz
    fldz
    fldz
    fldz
    fldz
    fldz
    fldz
    fninit

    /* Ensure FPU is set to double extended precision */
    fldcw [RIP + SYMBOL(fpu_cwd)]

    /* Set the bits of some of the vector regs to 1. This makes it easier to
     * detect certain zeroing behavior. */
    SET_VEC(0)
    SET_VEC(1)
    SET_VEC(2)
    SET_VEC(3)
    SET_VEC(4)
    SET_VEC(5)
    SET_VEC(6)
    SET_VEC(7)

    /* Set the rflags to what we want them to be. */
    push QWORD PTR [RIP + SYMBOL(gRflagsForTest)]
    popfq

    xchg RSP, [RIP + SYMBOL(gStackSwitcher)]  /* Switch onto recording stack. */

/* Save the native state into the lifted state structure. The native state
 * will go on to execute, and then at the end of the native testcase, the
 * native state will be saved into `gNativeState`, so that it can later be
 * compared with the end result of executing lifted code against
 * `gLiftedState`. */
# define STATE_PTR SYMBOL(gLiftedState)
# include "generated/Arch/X86/SaveState.S"
# undef STATE_PTR

    jmp QWORD PTR DS:[RIP + SYMBOL(gTestToRun)]
    .cfi_endproc

    .align 16
    .globl SYMBOL(InvokeTestCase)
SYMBOL(InvokeTestCase):
    .cfi_startproc
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    call SYMBOL(DoInvokeTestCase)
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret
    .cfi_endproc

    .align 16
SYMBOL(__x86_save_state_after):
    .cfi_startproc
# define STATE_PTR SYMBOL(gNativeState)
# define AFTER_TEST_CASE
# include "generated/Arch/X86/SaveState.S"
    xchg RSP, [RIP + SYMBOL(gStackSwitcher)]  /* Return to the normal stack. */
    fninit  /* Go back to a sane FPU */
    ret
    .cfi_endproc
# undef STATE_PTR

#else
    TEXT_SECTION
SYMBOL(InvokeTestCase):
SYMBOL(__x86_save_state_after):
    ud2;
    ret
#endif  /* IN_TEST_GENERATOR */

    /* Create a symbol that represents the start of the test information
     * table. */
    .section "__x86_test_table", "a"
    .balign 128
    .globl SYMBOL(__x86_test_table_begin)
SYMBOL(__x86_test_table_begin):
    TEXT_SECTION

/* For argument register and return register definitions. */

#include "tests/X86/ABI.S"
#include "tests/X86/MMX/INPUTS.S"


/* Change to `0` and put new `#include`s above when making new tests to speed
 * up compile and test times. */
#if 1

/* Bring in the data transfer tests. These basically HAVE to pass before
 * anything else can ;-)  */

#include "tests/X86/DATAXFER/MOV.S"
#include "tests/X86/DATAXFER/MOVAPD.S"
#include "tests/X86/DATAXFER/MOVAPS.S"
#include "tests/X86/DATAXFER/MOVBE.S"
#include "tests/X86/DATAXFER/MOVD.S"
#include "tests/X86/DATAXFER/MOVDQA.S"
#include "tests/X86/DATAXFER/MOVDQU.S"
#include "tests/X86/DATAXFER/MOVHLPS.S"
#include "tests/X86/DATAXFER/MOVHPD.S"
#include "tests/X86/DATAXFER/MOVHPS.S"
#include "tests/X86/DATAXFER/MOVLPD.S"
#include "tests/X86/DATAXFER/MOVLPS.S"
#include "tests/X86/DATAXFER/MOVLHPS.S"
#include "tests/X86/DATAXFER/MOVQ.S"
#include "tests/X86/DATAXFER/MOVSD.S"
#include "tests/X86/DATAXFER/MOVSS.S"
#include "tests/X86/DATAXFER/MOVSX.S"
#include "tests/X86/DATAXFER/MOVUPD.S"
#include "tests/X86/DATAXFER/MOVUPS.S"
#include "tests/X86/DATAXFER/MOVZX.S"
#include "tests/X86/DATAXFER/XCHG.S"
#include "tests/X86/DATAXFER/KMOVW.S"

/* Bring in the rest of the semantic tests. */

#include "tests/X86/AVX/VINSERTF128.S"
#include "tests/X86/AVX/VZEROUPPER.S"
#include "tests/X86/AVX/VPBROADCASTB.S"

#include "tests/X86/BINARY/ADC.S"
#include "tests/X86/BINARY/ADD.S"
#include "tests/X86/BINARY/ADDPD.S"
#include "tests/X86/BINARY/ADDPS.S"
#include "tests/X86/BINARY/ADDSD.S"
#include "tests/X86/BINARY/ADDSS.S"
#include "tests/X86/BINARY/CMP.S"
#include "tests/X86/BINARY/DEC.S"
#include "tests/X86/BINARY/DIV.S"
#include "tests/X86/BINARY/DIVPD.S"
#include "tests/X86/BINARY/DIVPS.S"
#include "tests/X86/BINARY/IDIV.S"
#include "tests/X86/BINARY/IMUL.S"
#include "tests/X86/BINARY/INC.S"
#include "tests/X86/BINARY/MUL.S"
#include "tests/X86/BINARY/MULPD.S"
#include "tests/X86/BINARY/MULPS.S"
#include "tests/X86/BINARY/MULSD.S"
#include "tests/X86/BINARY/MULSS.S"
#include "tests/X86/BINARY/MULX.S"
#include "tests/X86/BINARY/NEG.S"
#include "tests/X86/BINARY/SBB.S"
#include "tests/X86/BINARY/SUB.S"
#include "tests/X86/BINARY/SUBPD.S"
#include "tests/X86/BINARY/SUBPS.S"
#include "tests/X86/BINARY/SUBSD.S"
#include "tests/X86/BINARY/SUBSS.S"

#include "tests/X86/BITBYTE/BSF.S"
#include "tests/X86/BITBYTE/BSR.S"
#include "tests/X86/BITBYTE/BSWAP.S"
#include "tests/X86/BITBYTE/BT.S"
#include "tests/X86/BITBYTE/BTC.S"
#include "tests/X86/BITBYTE/BTR.S"
#include "tests/X86/BITBYTE/BTS.S"
#include "tests/X86/BITBYTE/LZCNT.S"
#include "tests/X86/BITBYTE/SETcc.S"
#include "tests/X86/BITBYTE/TZCNT.S"

#include "tests/X86/CMOV/CMOVB.S"
#include "tests/X86/CMOV/CMOVBE.S"
#include "tests/X86/CMOV/CMOVL.S"
#include "tests/X86/CMOV/CMOVLE.S"
#include "tests/X86/CMOV/CMOVNB.S"
#include "tests/X86/CMOV/CMOVNBE.S"
#include "tests/X86/CMOV/CMOVNL.S"
#include "tests/X86/CMOV/CMOVNLE.S"
#include "tests/X86/CMOV/CMOVNO.S"
#include "tests/X86/CMOV/CMOVNP.S"
#include "tests/X86/CMOV/CMOVNS.S"
#include "tests/X86/CMOV/CMOVNZ.S"
#include "tests/X86/CMOV/CMOVO.S"
#include "tests/X86/CMOV/CMOVP.S"
#include "tests/X86/CMOV/CMOVS.S"
#include "tests/X86/CMOV/CMOVZ.S"

#include "tests/X86/CONVERT/CBW.S"
#include "tests/X86/CONVERT/CDQ.S"
#include "tests/X86/CONVERT/CDQE.S"
#include "tests/X86/CONVERT/CQO.S"
#include "tests/X86/CONVERT/CVTDQ2PD.S"
#include "tests/X86/CONVERT/CVTDQ2PS.S"
#include "tests/X86/CONVERT/CVTPD2DQ.S"
#include "tests/X86/CONVERT/CVTPD2PS.S"
#include "tests/X86/CONVERT/CVTPI2PD.S"
#include "tests/X86/CONVERT/CVTPI2PS.S"
#include "tests/X86/CONVERT/CVTPS2DQ.S"
#include "tests/X86/CONVERT/CVTPS2PD.S"
#include "tests/X86/CONVERT/CVTSD2SI.S"
#include "tests/X86/CONVERT/CVTSD2SS.S"
#include "tests/X86/CONVERT/CVTSI2SD.S"
#include "tests/X86/CONVERT/CVTSI2SS.S"
#include "tests/X86/CONVERT/CVTSS2SD.S"
#include "tests/X86/CONVERT/CVTSS2SI.S"
#include "tests/X86/CONVERT/CVTTPD2DQ.S"
#include "tests/X86/CONVERT/CVTTPS2DQ.S"
#include "tests/X86/CONVERT/CVTTSD2SI.S"
#include "tests/X86/CONVERT/CVTTSS2SI.S"
#include "tests/X86/CONVERT/CWD.S"
#include "tests/X86/CONVERT/CWDE.S"

/* used for DECIMAL tests */
#include "tests/X86/DECIMAL/UTIL_FLAGS.S"
#include "tests/X86/DECIMAL/AAS.S"
#include "tests/X86/DECIMAL/DAA.S"

#include "tests/X86/LOGICAL/AND.S"
#include "tests/X86/LOGICAL/NOT.S"
#include "tests/X86/LOGICAL/OR.S"
#include "tests/X86/LOGICAL/TEST.S"
#include "tests/X86/LOGICAL/XOR.S"

#include "tests/X86/MISC/CPUID.S"
#include "tests/X86/MISC/ENTER.S"
#include "tests/X86/MISC/LEA.S"
#include "tests/X86/MISC/LEAVE.S"
#include "tests/X86/MISC/XLAT.S"

#include "tests/X86/MMX/MISC.S"
#include "tests/X86/MMX/PACKSS.S"
#include "tests/X86/MMX/PADD.S"
#include "tests/X86/MMX/PADDU.S"
#include "tests/X86/MMX/PCMP.S"
#include "tests/X86/MMX/PEXTR.S"
#include "tests/X86/MMX/PINSRW.S"
#include "tests/X86/MMX/PMOV.S"
#include "tests/X86/MMX/PMUL.S"
#include "tests/X86/MMX/PSADBW.S"
#include "tests/X86/MMX/PSHUF.S"
#include "tests/X86/MMX/PSIGN.S"
#include "tests/X86/MMX/PSLL.S"
#include "tests/X86/MMX/PSRL.S"
#include "tests/X86/MMX/PSUB.S"
#include "tests/X86/MMX/PUNPCK.S"
#include "tests/X86/MMX/POR.S"

#include "tests/X86/POP/POP.S"
#include "tests/X86/POP/POPF.S"

#include "tests/X86/PUSH/PUSH.S"
#include "tests/X86/PUSH/PUSHF.S"

#include "tests/X86/ROTATE/RCL.S"
#include "tests/X86/ROTATE/RCR.S"
#include "tests/X86/ROTATE/ROL.S"
#include "tests/X86/ROTATE/ROR.S"

#include "tests/X86/SEMAPHORE/CMPXCHG.S"
#include "tests/X86/SEMAPHORE/CMPXCHG16B.S"
#include "tests/X86/SEMAPHORE/CMPXCHG8B.S"
#include "tests/X86/SEMAPHORE/XADD.S"

#include "tests/X86/SHIFT/SAR.S"
#include "tests/X86/SHIFT/SHL.S"
#include "tests/X86/SHIFT/SHLD.S"
#include "tests/X86/SHIFT/SHR.S"
#include "tests/X86/SHIFT/SHRD.S"

#include "tests/X86/SSE/CMPSS.S"
#include "tests/X86/SSE/COMISD.S"
#include "tests/X86/SSE/COMISS.S"
#include "tests/X86/SSE/PACKUSWB.S"
#include "tests/X86/SSE/PCMPISTRI.S"
#include "tests/X86/SSE/PSHUFD.S"
#include "tests/X86/SSE/PSHUFLW.S"
#include "tests/X86/SSE/PSHUFHW.S"
#include "tests/X86/SSE/PSLLDQ.S"
#include "tests/X86/SSE/PSRLDQ.S"
#include "tests/X86/SSE/UCOMISD.S"
#include "tests/X86/SSE/UCOMISS.S"
#include "tests/X86/SSE/MINSS.S"
#include "tests/X86/SSE/MINSD.S"
#include "tests/X86/SSE/MINPS.S"
#include "tests/X86/SSE/MAXSS.S"
#include "tests/X86/SSE/MAXSD.S"
#include "tests/X86/SSE/MAXPS.S"
#include "tests/X86/SSE/UNPCKLPD.S"
#include "tests/X86/SSE/UNPCKLPS.S"
#include "tests/X86/SSE/UNPCKHPD.S"
#include "tests/X86/SSE/UNPCKHPS.S"
#include "tests/X86/SSE/MOVDDUP.S"
#include "tests/X86/SSE/SQRTSS.S"
#include "tests/X86/SSE/SQRTSD.S"
#include "tests/X86/SSE/MXCSR.S"
#include "tests/X86/SSE/SHUFPS.S"
#include "tests/X86/SSE/SHUFPD.S"

#include "tests/X86/STRINGOP/CMPS.S"
#include "tests/X86/STRINGOP/LODS.S"
#include "tests/X86/STRINGOP/MOVS.S"
#include "tests/X86/STRINGOP/SCAS.S"
#include "tests/X86/STRINGOP/STOS.S"

#include "tests/X86/X87/FADD.S"
#include "tests/X86/X87/FBLD.S"
#include "tests/X86/X87/FBSTP.S"
#include "tests/X86/X87/FCMOV.S"
#include "tests/X86/X87/FCOM.S"
#include "tests/X86/X87/FDIV.S"
#include "tests/X86/X87/FLD.S"
#include "tests/X86/X87/FMUL.S"
#include "tests/X86/X87/FSUB.S"
#include "tests/X86/X87/FST.S"
#include "tests/X86/X87/FUCOM.S"
#include "tests/X86/X87/FXCH.S"
#include "tests/X86/X87/MISC.S"
#include "tests/X86/X87/FNINIT.S"

#include "tests/X86/FMA/VFMADDSD.S"
#include "tests/X86/FMA/VFMSUBSD.S"

#endif

    /* Create a symbol that represents the end of the test information table. */
    .section "__x86_test_table", "a"
    .globl SYMBOL(__x86_test_table_end)
SYMBOL(__x86_test_table_end):
