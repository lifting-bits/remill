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

/* Note:    Apple mangles C symbol names to have a leading underscore. */
#ifdef __APPLE__
# define SYMBOL(x) _ ## x
#else
# define SYMBOL(x) x
#endif

/* In the generator build, we "stub-out" the lifted function. In the Run build,
 * we reference it as an external that will get linked in.
 */
#ifdef IN_TEST_GENERATOR
# define DECLARE_LIFTED_FUNC(x) \
    .globl LIFTED_FUNC(x) ; \
    LIFTED_FUNC(x): ud2 ;
#else
# define DECLARE_LIFTED_FUNC(x) \
    .extern LIFTED_FUNC(x)
#endif

/* This is the name of the function that will be generated. */
#define TEST_FUNC(instr_name) \
    SYMBOL(X86_TEST_ ## instr_name)

/* This is the name what we will give to the lifted function. */
#define LIFTED_FUNC(instr_name) \
    SYMBOL(X86_LIFTED_ ## instr_name)

/* Defines the beginning of a test function. The key detail is that tests
 * register themselves into data structures located in a special section of
 * the binary.
 *
 * Each test function is associated with a `struct TestInfo` (see Test.h). These
 * structures are placed into the `__x86_test_table` section of the binary, and
 * bracketed by the `__x86_test_table_begin` and `__x86_test_table_end`
 * symbols, respectively.
 */
#define TEST_BEGIN(instr_name) \
    .file __FILE__ ; \
    .text ; \
    DECLARE_LIFTED_FUNC(instr_name) ; \
    .align 16 ; \
    .globl TEST_FUNC(instr_name) ; \
TEST_FUNC(instr_name): ; \
    995: \
    .data ; \
    996: \
    .asciz #instr_name ; \
    .section "__x86_test_table", "a" ; \
    .balign 4 ; \
    1: \
    .long 995b - 1b ; \
    .long 999f - 1b ; \
    .long 996b - 1b ; \
    .long 997f - 1b ; \
    .long 998f - 1b ; \
    .long LIFTED_FUNC(instr_name) - 1b; \
    .text ; \
    .cfi_startproc ;

/* Specify where the instruction to be tested begins and ends. We will decode
 * and disassemble this instruction so that, for each test, we can print out
 * the specific instruction targeted by that test.
 */
#define TEST_INSTR(...) \
    997: __VA_ARGS__ ; \
    998:

/* Note:    The test end address is placed *before* the `RET` so that we can
 *          make sure that the end of a test marker is actually
 *          `__mcsema_error`. This is kind of a hack.
 */
#define TEST_END(instr_name) \
    999: \
    ret ; \
    .cfi_endproc ;

/* Specify the beginning and end of a 64-bit-specific test.
 *
 * Note:    64-bit tests are elided in 32-bit builds be turning the whole test
 *          into a macro that is never expanded.
 */
#if 64 == ADDRESS_SIZE_BITS
# define TEST_BEGIN_64 TEST_BEGIN
# define TEST_END_64 TEST_END
#else
# define TEST_BEGIN_64(instr_name) \
      .macro IGNORE_ ## instr_name ## __LINE__
# define TEST_END_64(instr_name) \
      .endm ;
#endif  /* 64 == ADDRESS_SIZE_BITS */

/* Specify the beginning and end of an AVX-specific test.
 *
 * Note:    AVX tests are elided in 32-bit builds be turning the whole test
 *          into a macro that is never expanded.
 */
#if HAS_FEATURE_AVX
# define TEST_BEGIN_AVX TEST_BEGIN
# define TEST_END_AVX TEST_END
#else
# define TEST_BEGIN_AVX(instr_name) \
      .macro IGNORE_ ## instr_name ## __LINE__
# define TEST_END_AVX(instr_name) \
      .endm ;
#endif  /* HAS_FEATURE_AVX */

/* Specify the beginning and end of an AVX512-specific test.
 *
 * Note:    AVX512 tests are elided in 32-bit builds be turning the whole test
 *          into a macro that is never expanded.
 */
#if HAS_FEATURE_AVX512
# define TEST_BEGIN_AVX512 TEST_BEGIN
# define TEST_END_AVX512 TEST_END
#else
# define TEST_BEGIN_AVX512(instr_name) \
      .macro IGNORE_ ## instr_name ## __LINE__
# define TEST_END_AVX512(instr_name) \
      .endm ;
#endif  /* HAS_FEATURE_AVX512 */

    .file __FILE__ ;
    .intel_syntax noprefix ;
    .text ;

/* Create a symbol that represents the start of the test information table. */
    .section "__x86_test_table", "a" ;
    .balign 4 ;
    .globl SYMBOL(__x86_test_table_begin) ;
SYMBOL(__x86_test_table_begin):
    .text ;

/* Bring in all semantic tests. */
#include "tests/X86/BINARY/ADD.S"

/* Create a symbol that represents the end of the test information table. */
    .section "__x86_test_table", "a" ;
    .balign 4 ;
    .globl SYMBOL(__x86_test_table_end) ;
SYMBOL(__x86_test_table_end):

#endif  /* TESTS_X86_TESTS_S_ */
