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
 * we reference it as an external that will get linked in.
 */
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
 * Note: Double `SYMBOL`ization of the reference to the lifted func.
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
    .balign 8 ; \
    2: \
    .long 3f - 2b ; \
    .long 6f - 2b ; \
    .long 1b - 2b ; \
    .long 4f - 2b ; \
    .long 5f - 2b ; \
    .long SYMBOL(LIFTED_FUNC(instr_name, num_args)) - 2b; \
    .long num_args ; \
    .long 0 ; \
    \
    .text ; \
    3: \
    .cfi_startproc ;

/* Specify where the instruction to be tested begins and ends. We will decode
 * and disassemble this instruction so that, for each test, we can print out
 * the specific instruction targeted by that test.
 */
#define TEST_INSTR(...) \
    4: __VA_ARGS__ ; \
    5:

/* Note:    The test end address is placed *before* the `RET` so that we can
 *          make sure that the end of a test marker is actually
 *          `__mcsema_error`. This is kind of a hack.
 */
#define TEST_END \
    6: \
    ret ; \
    .cfi_endproc ;

/* Specify the beginning and end of a 64-bit-specific test.
 *
 * Note:    64-bit tests are elided in 32-bit builds be turning the whole test
 *          into a macro that is never expanded.
 */
#if 64 == ADDRESS_SIZE_BITS
# define TEST_BEGIN_64(instr_name, num_args) \
    TEST_BEGIN(instr_name ## _64, num_args)
# define TEST_END_64 TEST_END
#else
# define TEST_BEGIN_64(instr_name, num_args) \
      .macro IGNORE_ ## instr_name ## __LINE__
# define TEST_END_64 \
      .endm ;
#endif  /* 64 == ADDRESS_SIZE_BITS */

    .file __FILE__ ;
    .intel_syntax noprefix ;

    /* Create a symbol that represents the start of the test information
     * table. */
    .section "__x86_test_table", "a" ;
    .balign 8 ;
    .globl SYMBOL(__x86_test_table_begin) ;
SYMBOL(__x86_test_table_begin):
    .text ;

/* For argument register and return register definitions. */
#include "tests/X86/ABI.S"

/* Bring in all semantic tests. */
#include "tests/X86/BINARY/ADD.S"

    /* Create a symbol that represents the end of the test information table. */
    .section "__x86_test_table", "a" ;
    .balign 8 ;
    .globl SYMBOL(__x86_test_table_end) ;
SYMBOL(__x86_test_table_end):

    /* Reset */
    .att_syntax prefix ;

#endif  /* TESTS_X86_TESTS_S_ */
