/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TESTS_X86_TESTS_S_
#define TESTS_X86_TESTS_S_

#ifndef ADDRESS_SIZE_BITS
# define ADDRESS_SIZE_BITS 64
#endif

#ifndef HAS_FEATURE_AVX
# define HAS_FEATURE_AVX 1
#endif

#ifndef HAS_FEATURE_AVX512
# define HAS_FEATURE_AVX512 1
#endif

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

/* In the generator build, we "stub-out" the lifted function. In the Run build,
 * we reference it as an external that will get linked in. */
#ifdef IN_TEST_GENERATOR
# define DECLARE_LIFTED_FUNC(x, num_args) \
    .globl LIFTED_FUNC(x, num_args) ; \
LIFTED_FUNC(x, num_args): \
    nop ;
#else
# define DECLARE_LIFTED_FUNC(x, num_args) \
    .extern LIFTED_FUNC(x, num_args) ;
#endif

#define FUNC_NAME(instr_name, num_args) \
    CAT3(instr_name, _, num_args)

/* This is the name of the function that will be generated. */
#define TEST_FUNC(instr_name, num_args) \
    SYMBOL(CAT3(X86_TEST, _, FUNC_NAME(instr_name, num_args)))

/* This is the name what we will give to the lifted function. */
#define LIFTED_FUNC(instr_name, num_args) \
    SYMBOL(CAT3(X86_LIFTED, _, FUNC_NAME(instr_name, num_args)))

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
    .file __FILE__ ; \
    .text ; \
    \
    DECLARE_LIFTED_FUNC(instr_name, num_args) ; \
    \
    .align 16 ; \
    .globl TEST_FUNC(instr_name, num_args) ; \
    \
TEST_FUNC(instr_name, num_args): ; \
    .data ; \
    1: \
    .asciz TO_STRING(FUNC_NAME(instr_name, num_args)) ; \
    \
    .section "__x86_test_table", "a" ; \
    .balign 128 ; \
    2: \
    .quad 3f ; \
    .quad 6f ; \
    .quad 1b ; \
    .quad 4f ; \
    .quad 5f ; \
    .quad LIFTED_FUNC(instr_name, num_args) ; \
    .quad num_args ; \
    \
    .text ; \
    3: \
    .cfi_startproc ;

/* Note:    The test end address is placed *before* the `RET` so that we can
 *          make sure that the end of a test marker is actually
 *          `__remill_error`. This is kind of a hack.
 */
#ifdef IN_TEST_GENERATOR
# define TEST_END \
    6: \
    .cfi_endproc ; \
    .section "__x86_test_table", "a" ; \
    .quad 0 ; \
    .text ;
#else
# define TEST_END \
    6: \
    jmp SYMBOL(__x86_save_state_after) ; \
    .cfi_endproc ; \
    .section "__x86_test_table", "a" ; \
    .quad 0 ; \
    .text ;
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

    .file __FILE__ ;
    .intel_syntax noprefix ;

#ifndef IN_TEST_GENERATOR
    .data
    .extern SYMBOL(gTestToRun)
    .extern SYMBOL(gLiftedState)
    .extern SYMBOL(gNativeState)
    .extern SYMBOL(gStackSwitcher)
    .extern SYMBOL(gTestEnd)
    .extern SYMBOL(gStackSaveSlot)

    .data
    .align 16
SYMBOL(vec_data):
    .long 0x41414141, 0xabababab, 0xcdcdcdcd, 0xefefefef
    .long 0x29292929, 0x38383838, 0x47474747, 0x56565656
    .long 0x37373737, 0x82828282, 0x1a1a1a1a, 0x2b2b2b2b
    .long 0x96969696, 0x35353535, 0xaeaeaeae, 0xc4c4c4c4
    .long 0x3d3d3d3d, 0x21212121, 0x11223344, 0x55667788

// Set all bits in a vector.
#if HAS_FEATURE_AVX
# define SET_VEC(num) vmovdqu ymm ## num , [RIP + SYMBOL(vec_data) + (num*16)]
#else
# define SET_VEC(num) movdqu xmm ## num , [RIP + SYMBOL(vec_data) + (num*16)]
#endif

    /* This function tail-calls to the test that we want to run via the
     * `gTestToRun` pointer.
     */
    .text
    .align 16
    .globl SYMBOL(DoInvokeTestCase)
SYMBOL(DoInvokeTestCase):
    .cfi_startproc

    /* Set the bits of some of the vector regs to 1. This makes it easier to
     * detect certain zeroing behavior. */
    SET_VEC(0)
    SET_VEC(1)
    SET_VEC(2)
    SET_VEC(3)

    xchg RSP, [RIP + SYMBOL(gStackSwitcher)]  /* Switch onto recording stack. */
# define STATE_PTR SYMBOL(gLiftedState)
# include "tests/X86/SaveState.S"
    jmp QWORD PTR DS:[RIP + SYMBOL(gTestToRun)]
    .cfi_endproc
# undef STATE_PTR

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
# include "tests/X86/SaveState.S"
    xchg RSP, [RIP + SYMBOL(gStackSwitcher)]  /* Return to the normal stack. */
    ret
    .cfi_endproc
# undef STATE_PTR

#else
    .text
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
    .text

/* For argument register and return register definitions. */
#include "tests/X86/ABI.S"

#define APPLE_SAFE_TESTS (!defined(__APPLE__) || 64 == ADDRESS_SIZE_BITS)


/* Bring in the data transfer tests. These basically HAVE to pass before
 * anything else can ;-)  */
#include "tests/X86/DATAXFER/MOV.S"
#include "tests/X86/DATAXFER/MOVAPD.S"
#include "tests/X86/DATAXFER/MOVAPS.S"
#include "tests/X86/DATAXFER/MOVD.S"
#include "tests/X86/DATAXFER/MOVDQA.S"
#include "tests/X86/DATAXFER/MOVDQU.S"
#include "tests/X86/DATAXFER/MOVLPD.S"
#include "tests/X86/DATAXFER/MOVLPS.S"
#include "tests/X86/DATAXFER/MOVQ.S"
#include "tests/X86/DATAXFER/MOVSD.S"
#include "tests/X86/DATAXFER/MOVSS.S"
#include "tests/X86/DATAXFER/MOVSX.S"
#include "tests/X86/DATAXFER/MOVUPD.S"
#include "tests/X86/DATAXFER/MOVUPS.S"
#include "tests/X86/DATAXFER/MOVZX.S"
#include "tests/X86/DATAXFER/XCHG.S"


/* Bring in the rest of the semantic tests. */

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
#include "tests/X86/BINARY/XADD.S"

#include "tests/X86/BITBYTE/BT.S"
#include "tests/X86/BITBYTE/BTC.S"
#include "tests/X86/BITBYTE/BTR.S"
#include "tests/X86/BITBYTE/BTS.S"
#include "tests/X86/BITBYTE/SETcc.S"

/*

#include "tests/X86/CONVERT/CBW.S"
#include "tests/X86/CONVERT/CDQ.S"
#include "tests/X86/CONVERT/CDQE.S"
#include "tests/X86/CONVERT/CQO.S"
#include "tests/X86/CONVERT/CWD.S"
#include "tests/X86/CONVERT/CWDE.S"

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

#if APPLE_SAFE_TESTS
# include "tests/X86/POP/POP.S"
# include "tests/X86/POP/POPF.S"

# include "tests/X86/PUSH/PUSH.S"
# include "tests/X86/PUSH/PUSHF.S"
#endif  // APPLE_SAFE_TESTS

#include "tests/X86/ROTATE/RCL.S"
#include "tests/X86/ROTATE/RCR.S"
#include "tests/X86/ROTATE/ROL.S"
#include "tests/X86/ROTATE/ROR.S"

#include "tests/X86/SHIFT/SAR.S"
#include "tests/X86/SHIFT/SHL.S"
#include "tests/X86/SHIFT/SHLD.S"
#include "tests/X86/SHIFT/SHR.S"
#include "tests/X86/SHIFT/SHRD.S"

#include "tests/X86/SSE/COMISD.S"
#include "tests/X86/SSE/COMISS.S"
#include "tests/X86/SSE/UCOMISD.S"
#include "tests/X86/SSE/UCOMISS.S"

#if APPLE_SAFE_TESTS
# include "tests/X86/STRINGOP/CMPS.S"
# include "tests/X86/STRINGOP/LODS.S"
# include "tests/X86/STRINGOP/MOVS.S"
# include "tests/X86/STRINGOP/SCAS.S"
# include "tests/X86/STRINGOP/STOS.S"
#endif  // __APPLE__
*/
    /* Create a symbol that represents the end of the test information table. */
    .section "__x86_test_table", "a"
    .globl SYMBOL(__x86_test_table_end)
SYMBOL(__x86_test_table_end):

    /* Reset */
    .att_syntax prefix

#endif  /* TESTS_X86_TESTS_S_ */
