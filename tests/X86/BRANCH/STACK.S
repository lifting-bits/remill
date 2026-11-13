/* SPDX-License-Identifier: Apache-2.0 */

/* The native harness runs in long mode. For a 32-bit guest, model the
 * four-byte CALL/RET stack operations explicitly; the generator still lifts
 * the real instructions. Equal-sized sequences keep return-PC offsets equal.
 * R11 is scratch in the reference only: it is not a 32-bit guest register. */
.macro TEST_CALL target
#if ADDRESS_SIZE_BITS == 32
.Ltest_call_start\@:
#ifdef IN_TEST_GENERATOR
    .fill 27, 1, 0x90
    call \target
#else
    lea rsp, [rsp - 4]
    mov DWORD PTR [rsp], OFFSET .Ltest_call_return\@
    jmp \target
    .org .Ltest_call_start\@ + 32, 0x90
#endif
.Ltest_call_return\@:
#else
    call \target
#endif
.endm

.macro TEST_RET
#if ADDRESS_SIZE_BITS == 32
.Ltest_ret_start\@:
#ifdef IN_TEST_GENERATOR
    ret
#else
    mov r11d, DWORD PTR [rsp]
    lea rsp, [rsp + 4]
    jmp r11
#endif
    .org .Ltest_ret_start\@ + 16, 0x90
#else
    ret
#endif
.endm
