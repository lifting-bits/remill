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

/* We want to be able to describe what high-level feature set is used by a
 * particular test case. This feature information is recorded in the `TestInfo`
 * structure.
 *
 * Note: This is pretty ugly but it works :-) We use macro concatenation
 *       against variadic macro arguments, hence things like `FEATURE_`,
 *       which represents a concatenation of `FEATURE_` with an empty
 *       `__VA_ARGS__`.
 */

/* Features of tests that work for both 32- and 64-bit code. */
#define FEATURE_        0
#define FEATURE_MMX     1
#define FEATURE_SSE     (2 | FEATURE_MMX)
#define FEATURE_AVX     (4 | FEATURE_SSE)
#define FEATURE_AVX512  (8 | FEATURE_AVX | FEATURE_SSE)
#define FEATURE_64BIT   16
#define FEATURE_32BIT   32

/* Features of 64-bit only tests. */
#define FEATURE_B64_ FEATURE_64BIT
#define FEATURE_B64_MMX (FEATURE_64BIT | FEATURE_MMX)
#define FEATURE_B64_SSE (FEATURE_64BIT | FEATURE_SSE)
#define FEATURE_B64_AVX (FEATURE_64BIT | FEATURE_AVX)
#define FEATURE_B64_AVX512 (FEATURE_64BIT | FEATURE_AVX512)

/* Features of 32-bit only tests. */
#define FEATURE_B32_ FEATURE_32BIT
#define FEATURE_B32_MMX (FEATURE_32BIT | FEATURE_MMX)
#define FEATURE_B32_SSE (FEATURE_32BIT | FEATURE_SSE)
#define FEATURE_B32_AVX (FEATURE_32BIT | FEATURE_AVX)
#define FEATURE_B32_AVX512 (FEATURE_32BIT | FEATURE_AVX512)

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
#define TEST_BEGIN(instr_name, num_args, ...) \
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
    .long num_args ; \
    .long FEATURE_ ## __VA_ARGS__ ; \
    \
    .text ; \
    3: \
    .cfi_startproc ;

/* Note:    The test end address is placed *before* the `RET` so that we can
 *          make sure that the end of a test marker is actually
 *          `__mcsema_error`. This is kind of a hack.
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
# define TEST_BEGIN_64(instr_name, num_args, ...) \
    TEST_BEGIN(instr_name ## _64, num_args, B64_ ## __VA_ARGS__)
# define TEST_END_64 TEST_END
# define TEST_BEGIN_32(instr_name, num_args) \
      .macro IGNORE_ ## instr_name ## __LINE__
# define TEST_END_32 \
      .endm ;
#else
# define TEST_BEGIN_64(instr_name, num_args) \
      .macro IGNORE_ ## instr_name ## __LINE__
# define TEST_END_64 \
      .endm ;
# define TEST_BEGIN_32(instr_name, num_args, ...) \
    TEST_BEGIN(instr_name ## _32, num_args, B32_ ## __VA_ARGS__)
# define TEST_END_32 TEST_END
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

    .text


// Set all bits in a vector.
#if HAS_FEATURE_AVX
# define SET_VEC(num) vpcmpeqw ymm ## num , ymm ## num , ymm ## num
#else
# define SET_VEC(num) pcmpeqw xmm ## num , xmm ## num
#endif


    /* This function tail-calls to the test that we want to run via the
     * `gTestToRun` pointer.
     */
    .align 16
    .globl SYMBOL(InvokeTestCase)
SYMBOL(InvokeTestCase):
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
SYMBOL(__x86_save_state_after):
    .cfi_startproc
# define STATE_PTR SYMBOL(gNativeState)
# define AFTER_TEST_CASE
# include "tests/X86/SaveState.S"
    xchg rsp, [RIP + SYMBOL(gStackSwitcher)]  /* Return to the normal stack. */
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

/* Bring in all semantic tests. */

#include "tests/X86/BINARY/ADC.S"
#include "tests/X86/BINARY/ADD.S"
#include "tests/X86/BINARY/CMP.S"
#include "tests/X86/BINARY/DEC.S"
#include "tests/X86/BINARY/DIV.S"
#include "tests/X86/BINARY/IDIV.S"
#include "tests/X86/BINARY/IMUL.S"
#include "tests/X86/BINARY/INC.S"
#include "tests/X86/BINARY/MUL.S"
#include "tests/X86/BINARY/MULX.S"
#include "tests/X86/BINARY/NEG.S"
#include "tests/X86/BINARY/SBB.S"
#include "tests/X86/BINARY/SUB.S"
#include "tests/X86/BINARY/XADD.S"

#include "tests/X86/BITBYTE/BT.S"
#include "tests/X86/BITBYTE/BTC.S"
#include "tests/X86/BITBYTE/BTR.S"
#include "tests/X86/BITBYTE/BTS.S"

#include "tests/X86/CONVERT/CBW.S"
#include "tests/X86/CONVERT/CDQ.S"
#include "tests/X86/CONVERT/CDQE.S"
#include "tests/X86/CONVERT/CQO.S"
#include "tests/X86/CONVERT/CWD.S"
#include "tests/X86/CONVERT/CWDE.S"

#include "tests/X86/DATAXFER/MOVAPS.S"
#include "tests/X86/DATAXFER/MOVD.S"
#include "tests/X86/DATAXFER/MOVQ.S"
#include "tests/X86/DATAXFER/MOVUPS.S"
#include "tests/X86/DATAXFER/XCHG.S"

#include "tests/X86/LOGICAL/AND.S"
#include "tests/X86/LOGICAL/NOT.S"
#include "tests/X86/LOGICAL/OR.S"
#include "tests/X86/LOGICAL/TEST.S"
#include "tests/X86/LOGICAL/XOR.S"

#include "tests/X86/ROTATE/ROL.S"

#include "tests/X86/SHIFT/SAR.S"
#include "tests/X86/SHIFT/SHL.S"
#include "tests/X86/SHIFT/SHR.S"
#include "tests/X86/SHIFT/SHRD.S"

#ifndef __APPLE__
# include "tests/X86/STRINGOP/CMPS.S"
# include "tests/X86/STRINGOP/LODS.S"
# include "tests/X86/STRINGOP/MOVS.S"
# include "tests/X86/STRINGOP/SCAS.S"
# include "tests/X86/STRINGOP/STOS.S"
#endif  // __APPLE__

    /* Create a symbol that represents the end of the test information table. */
    .section "__x86_test_table", "a"
    .globl SYMBOL(__x86_test_table_end)
SYMBOL(__x86_test_table_end):

    /* Reset */
    .att_syntax prefix

#endif  /* TESTS_X86_TESTS_S_ */
