/* SPDX-License-Identifier: Apache-2.0 */

#if ADDRESS_SIZE_BITS == 32
#ifdef IN_TEST_GENERATOR
    .code32
#endif

TEST_BEGIN(POPA16_SKIP_SP, 1)
TEST_INPUTS(0)
    lea SP_ADDR, [SP_ADDR - 16]
    mov DWORD PTR [SP_ADDR], 0xa001a000
    mov DWORD PTR [SP_ADDR + 4], 0xdeada002
    mov DWORD PTR [SP_ADDR + 8], 0xa005a004
    mov DWORD PTR [SP_ADDR + 12], 0xa007a006
    mov edi, 0x12340000
    mov esi, 0x12340001
    mov ebp, 0x12340002
    mov ebx, 0x12340004
    mov edx, 0x12340005
    mov ecx, 0x12340006
    mov eax, 0x12340007
#ifdef IN_TEST_GENERATOR
    .byte 0x66, 0x61
#else
    /* The native harness runs in long mode, where POPA is invalid. Use the
     * equivalent individual loads as the reference, including the SP skip. */
    pop di
    pop si
    pop bp
    lea rsp, [rsp + 2]
    pop bx
    pop dx
    pop cx
    pop ax
#endif
TEST_END

TEST_BEGIN(POPAD32_SKIP_ESP, 1)
TEST_INPUTS(0)
    lea SP_ADDR, [SP_ADDR - 32]
    mov DWORD PTR [SP_ADDR], 0xa1230000
    mov DWORD PTR [SP_ADDR + 4], 0xa1230001
    mov DWORD PTR [SP_ADDR + 8], 0xa1230002
    mov DWORD PTR [SP_ADDR + 12], 0xdeadbeef
    mov DWORD PTR [SP_ADDR + 16], 0xa1230004
    mov DWORD PTR [SP_ADDR + 20], 0xa1230005
    mov DWORD PTR [SP_ADDR + 24], 0xa1230006
    mov DWORD PTR [SP_ADDR + 28], 0xa1230007
#ifdef IN_TEST_GENERATOR
    .byte 0x61
#else
    mov edi, DWORD PTR [rsp]
    mov esi, DWORD PTR [rsp + 4]
    mov ebp, DWORD PTR [rsp + 8]
    mov ebx, DWORD PTR [rsp + 16]
    mov edx, DWORD PTR [rsp + 20]
    mov ecx, DWORD PTR [rsp + 24]
    mov eax, DWORD PTR [rsp + 28]
    lea rsp, [rsp + 32]
#endif
TEST_END

#ifdef IN_TEST_GENERATOR
    .code64
#endif
#endif
