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

/* Defines the beginning of a test function. The key detail is that tests
 * register themselves into data structures located in a special section of
 * the binary.
 *
 * Each test function is associated with a `struct TestInfo` (see Test.h). These
 * structures are placed into the `__aarch64_test_table` section of the binary,
 * and bracketed by the `__aarch64_test_table_begin` and
 * `__aarch64_test_table_end` symbols, respectively.
 */
#define TEST_BEGIN(instr_name, num_args) \
    .text ; \
    \
    .align 16 ; \
    .globl SYMBOL(FUNC_NAME(instr_name, num_args)) ; \
    \
SYMBOL(FUNC_NAME(instr_name, num_args)): ; \
    .data ; \
    1: \
    .asciz TO_STRING(FUNC_NAME(instr_name, num_args)) ; \
    \
    .section "__aarch64_test_table", "a" ; \
    .balign 128 ; \
    2: \
    .quad 3f ; \
    .quad 6f ; \
    .quad 1b ; \
    .quad 4f ; \
    .quad 5f ; \
    .quad num_args ; \
    \
    .text ; \
    adrp    x30, SYMBOL(gNativeState) \
    add     x30, x30, :lo12:SYMBOL(gNativeState) \
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
    .section "__aarch64_test_table", "a" ; \
    .quad 0 ; \
    .text ; \
    hlt #0 ;

#else
# define TEST_END \
    6: \
    b SYMBOL(__aarch64_save_state_after) ; \
    .cfi_endproc ; \
    .section "__aarch64_test_table", "a" ; \
    .quad 0 ; \
    .text ; \
    hlt #0 ;
#endif

#ifndef IN_TEST_GENERATOR
    .data
    .extern SYMBOL(gTestToRun)
    .extern SYMBOL(gLiftedState)
    .extern SYMBOL(gNativeState)
    .extern SYMBOL(gStackSwitcher)
    .extern SYMBOL(gTestEnd)
    .extern SYMBOL(gStackSaveSlot)
#endif  /* IN_TEST_GENERATOR */

    .text

#ifndef IN_TEST_GENERATOR
    .align 16
    .globl SYMBOL(InvokeTestCase)
SYMBOL(InvokeTestCase):
    .cfi_startproc

    /* Change stacks */
    mov     x30, sp
    adr     x30, SYMBOL(gStackSaveSlot)
    str     x30, [x30, #0]
    ldr     x30, SYMBOL(gStackSwitcher)
    mov     sp, x30

    /* Start by saving the current native state into the `gLiftedState`
     * structure. This will be used as the initial state when running the
     * lifted tests. */
    adrp    x30, SYMBOL(gLiftedState)
    add     x30, x30, :lo12:SYMBOL(gLiftedState)
#include "generated/Arch/AArch64/SaveState.S"

    /* Branch to the test to run */
    adrp    x30, SYMBOL(gTestToRun)
    add     x30, x30, :lo12:SYMBOL(gTestToRun)
    br      x30

    .cfi_endproc

    .align 16
    .globl SYMBOL(__aarch64_save_state_after)
SYMBOL(__aarch64_save_state_after):
    .cfi_startproc
    /* Save the current native state into the `gNativeState`, which now
     * contains the post-test state for eventual comparison against lifted
     * execution. Finally, go and restore the originally saved state. */
    adrp    x30, SYMBOL(gLiftedState)
    add     x30, x30, :lo12:SYMBOL(gLiftedState)
#include "generated/Arch/AArch64/SaveState.S"
#include "generated/Arch/AArch64/RestoreState.S"

    ldr     x30, SYMBOL(gStackSaveSlot)
    mov     sp, x30

    ret
    .cfi_endproc
#endif  /* IN_TEST_GENERATOR */

     /* Create a symbol that represents the beginning of the test
      * information table. */
    .section "__aarch64_test_table", "a"
    .globl SYMBOL(__aarch64_test_table_begin)
SYMBOL(__aarch64_test_table_begin):

     /* Create a symbol that represents the end of the test information table. */
    .section "__aarch64_test_table", "a"
    .globl SYMBOL(__aarch64_test_table_end)
SYMBOL(__aarch64_test_table_end):

